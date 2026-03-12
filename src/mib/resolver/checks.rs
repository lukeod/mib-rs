use std::collections::{HashMap, HashSet};

use crate::ir;
use crate::types::{Access, AccessKeyword, BaseType, DiagCode, Kind, Language, Span, Status};

use super::super::types::{ModuleId, NodeId, ObjectId, TypeId};
use super::context::{IrModuleId, ResolverContext};

struct Diag {
    code: DiagCode,
    ir_id: Option<IrModuleId>,
    span: Span,
    message: String,
}

/// Run post-resolution validation checks.
pub(super) fn run_checks(ctx: &mut ResolverContext) {
    check_access_and_status(ctx);
    check_node_parent_kinds(ctx);
    check_table_row_naming(ctx);
    check_description_missing(ctx);
    check_integer_misuse(ctx);
    check_trap_in_smiv2(ctx);
    check_type_unreferenced(ctx);
    check_named_number_ordering(ctx);
    check_range_constraints(ctx);
    check_type_assignment_smiv2(ctx);
    check_tc_nested(ctx);
    check_opaque_smiv2(ctx);
    check_notification_reversibility(ctx);
    check_node_implicit(ctx);
    check_identifier_case_match(ctx);
    check_status_per_version(ctx);
    check_sequence_fields(ctx);
    check_group_membership(ctx);
    check_group_member_locality(ctx);
    check_compliance_structure(ctx);
    check_module_identity_registration(ctx);
    check_row_status_defaults(ctx);
    check_storage_type_defaults(ctx);
    check_taddress_tdomain(ctx);
    check_inet_address_pairing(ctx);
    check_transport_address_pairing(ctx);
    check_defval_constraints(ctx);
    check_index_constraints(ctx);
    check_enum_subtyping(ctx);
    check_smiv2_identifier_hyphens(ctx);
    check_hyphen_in_label(ctx);
    check_format_hints(ctx);
    check_capabilities_status(ctx);
    check_type_status_usage(ctx);
    check_compliance_status(ctx);
    check_group_unreferenced(ctx);
    check_ip_address_deprecation(ctx);
}

fn emit_all(ctx: &mut ResolverContext, diags: Vec<Diag>) {
    for d in diags {
        ctx.emit_diagnostic(d.code, d.ir_id, d.span, d.message);
    }
}

/// Validate ACCESS and STATUS values per SMI version and node kind.
fn check_access_and_status(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };

            let node_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&ot.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let kind = ctx.mib.tree().get(node_id).kind;

            // Access keyword checks
            if m.language == Language::SMIv1 {
                // MIN-ACCESS is always SMIv2 (MODULE-COMPLIANCE), not applicable here.
                if ot.access_keyword == AccessKeyword::MaxAccess {
                    diags.push(Diag {
                        code: DiagCode::MaxAccessInSMIv1,
                        ir_id: Some(ir_id),
                        span: ot.span,
                        message: format!(
                            "{:?}: MAX-ACCESS is SMIv2 style, use ACCESS in SMIv1",
                            ot.name
                        ),
                    });
                }
                if ot.access == Access::WriteOnly {
                    diags.push(Diag {
                        code: DiagCode::AccessWriteOnlySMIv1,
                        ir_id: Some(ir_id),
                        span: ot.access_span,
                        message: format!("{}: write-only access is discouraged", ot.name),
                    });
                }
            } else if m.language == Language::SMIv2 {
                if ot.access_keyword == AccessKeyword::Access {
                    diags.push(Diag {
                        code: DiagCode::AccessInSMIv2,
                        ir_id: Some(ir_id),
                        span: ot.span,
                        message: format!(
                            "{:?}: ACCESS is SMIv1 style, use MAX-ACCESS in SMIv2",
                            ot.name
                        ),
                    });
                }
                if ot.access == Access::WriteOnly {
                    diags.push(Diag {
                        code: DiagCode::AccessWriteOnlySMIv2,
                        ir_id: Some(ir_id),
                        span: ot.span,
                        message: format!("{:?}: write-only is no longer allowed in SMIv2", ot.name),
                    });
                }
            }

            // Table/row access checks
            if kind == Kind::Table && ot.access != Access::NotAccessible {
                diags.push(Diag {
                    code: DiagCode::AccessTableIllegal,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!("{:?}: table must be not-accessible", ot.name),
                });
            }
            if kind == Kind::Row && ot.access != Access::NotAccessible {
                diags.push(Diag {
                    code: DiagCode::AccessRowIllegal,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!("{:?}: row must be not-accessible", ot.name),
                });
            }

            // Counter access check
            if let Some(type_id) = ctx
                .mib
                .tree()
                .get(node_id)
                .object
                .and_then(|oid| ctx.mib.raw().object(oid).typ)
            {
                let t = ctx.mib.raw().type_(type_id);
                let base = t.effective_base(ctx.mib.types_slice());
                if (base == BaseType::Counter32 || base == BaseType::Counter64)
                    && !matches!(ot.access, Access::ReadOnly | Access::AccessibleForNotify)
                {
                    diags.push(Diag {
                        code: DiagCode::AccessCounterIllegal,
                        ir_id: Some(ir_id),
                        span: ot.access_span,
                        message: format!(
                            "{}: counter must be read-only or accessible-for-notify",
                            ot.name
                        ),
                    });
                }
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate parent node kinds per SMI structural rules.
fn check_node_parent_kinds(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };

            let node_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&ot.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let node = ctx.mib.tree().get(node_id);
            let parent_id = match node.parent {
                Some(p) => p,
                None => continue,
            };
            if parent_id == ctx.mib.tree().root() {
                continue;
            }
            let parent_kind = ctx.mib.tree().get(parent_id).kind;

            match node.kind {
                Kind::Table => {
                    if !is_simple_parent_kind(parent_kind) {
                        diags.push(Diag {
                            code: DiagCode::ParentTable,
                            ir_id: Some(ir_id),
                            span: ot.span,
                            message: format!("{}: table's parent must be a simple node", ot.name),
                        });
                    }
                }
                Kind::Row => {
                    if parent_kind != Kind::Table {
                        diags.push(Diag {
                            code: DiagCode::ParentRow,
                            ir_id: Some(ir_id),
                            span: ot.span,
                            message: format!("{}: row's parent must be a table", ot.name),
                        });
                    } else if node.arc != 1 {
                        diags.push(Diag {
                            code: DiagCode::RowSubidentifierOne,
                            ir_id: Some(ir_id),
                            span: ot.span,
                            message: format!("{}: row must have sub-identifier 1", ot.name),
                        });
                    }
                }
                Kind::Column => {
                    if parent_kind != Kind::Row {
                        diags.push(Diag {
                            code: DiagCode::ParentColumn,
                            ir_id: Some(ir_id),
                            span: ot.span,
                            message: format!("{}: column's parent must be a row", ot.name),
                        });
                    }
                }
                Kind::Scalar => {
                    if !is_simple_parent_kind(parent_kind) {
                        diags.push(Diag {
                            code: DiagCode::ParentScalar,
                            ir_id: Some(ir_id),
                            span: ot.span,
                            message: format!("{}: scalar's parent must be a simple node", ot.name),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let (code, label) = match def {
                ir::Definition::Notification(_) => (DiagCode::ParentNotification, "notification"),
                ir::Definition::ObjectIdentity(_)
                | ir::Definition::ModuleIdentity(_)
                | ir::Definition::ValueAssignment(_) => (DiagCode::ParentNode, "node"),
                ir::Definition::ObjectGroup(_) | ir::Definition::NotificationGroup(_) => {
                    (DiagCode::ParentGroup, "group")
                }
                ir::Definition::ModuleCompliance(_) => (DiagCode::ParentCompliance, "compliance"),
                ir::Definition::AgentCapabilities(_) => {
                    (DiagCode::ParentCapabilities, "capabilities")
                }
                _ => continue,
            };

            let Some(node_id) = ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(def.name()))
                .copied()
            else {
                continue;
            };

            let node = ctx.mib.tree().get(node_id);
            let Some(parent_id) = node.parent else {
                continue;
            };
            if parent_id == ctx.mib.tree().root() {
                continue;
            }
            if !is_simple_parent_kind(ctx.mib.tree().get(parent_id).kind) {
                diags.push(Diag {
                    code,
                    ir_id: Some(ir_id),
                    span: def.span(),
                    message: format!(
                        "{:?}: {}'s parent node must be a simple node",
                        def.name(),
                        label
                    ),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

fn is_simple_parent_kind(k: Kind) -> bool {
    matches!(
        k,
        Kind::Node | Kind::Internal | Kind::Unknown | Kind::ModuleIdentity | Kind::ObjectIdentity
    )
}

/// Check table/row naming conventions.
fn check_table_row_naming(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };

            let node_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&ot.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let kind = ctx.mib.tree().get(node_id).kind;

            if kind == Kind::Table && !ot.name.ends_with("Table") {
                diags.push(Diag {
                    code: DiagCode::TableNameTable,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!("{}: table name should end with 'Table'", ot.name),
                });
            }

            if kind == Kind::Row && !ot.name.ends_with("Entry") {
                diags.push(Diag {
                    code: DiagCode::RowNameEntry,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!("{}: row name should end with 'Entry'", ot.name),
                });
            }

            // Check row name prefix matches table name prefix.
            if kind == Kind::Row {
                let node = ctx.mib.tree().get(node_id);
                if let Some(parent_id) = node.parent {
                    let parent = ctx.mib.tree().get(parent_id);
                    if parent.kind == Kind::Table {
                        let table_prefix =
                            parent.name.strip_suffix("Table").unwrap_or(&parent.name);
                        let row_prefix = ot.name.strip_suffix("Entry").unwrap_or(&ot.name);
                        if !table_prefix.is_empty()
                            && !row_prefix.is_empty()
                            && table_prefix != row_prefix
                        {
                            diags.push(Diag {
                                code: DiagCode::RowNameTableName,
                                ir_id: Some(ir_id),
                                span: ot.span,
                                message: format!(
                                    "{}: row prefix {:?} does not match table prefix {:?}",
                                    ot.name, row_prefix, table_prefix
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    emit_all(ctx, diags);
}

/// Warn when DESCRIPTION clause is missing in SMIv2.
fn check_description_missing(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };
            if !ot.has_description {
                diags.push(Diag {
                    code: DiagCode::DescriptionMissing,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!("{}: OBJECT-TYPE should have a DESCRIPTION clause", ot.name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

/// Flag bare INTEGER usage in SMIv2 (should use Integer32 for non-enum use).
fn check_integer_misuse(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            let (name, syntax, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, &ot.syntax, ot.span),
                ir::Definition::TypeDef(td) => (&td.name, &td.syntax, td.span),
                _ => continue,
            };
            if is_integer_keyword_syntax(syntax) {
                diags.push(Diag {
                    code: DiagCode::IntegerInSMIv2,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{}: use Integer32 instead of INTEGER in SMIv2", name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

fn is_integer_keyword_syntax(syntax: &ir::TypeSyntax) -> bool {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => name == "INTEGER",
        ir::TypeSyntax::Constrained { base, .. } => is_integer_keyword_syntax(base),
        _ => false,
    }
}

/// Warn about TRAP-TYPE usage in SMIv2 modules.
fn check_trap_in_smiv2(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            if let ir::Definition::Notification(n) = def
                && n.trap_info.is_some()
            {
                diags.push(Diag {
                    code: DiagCode::TrapInSMIv2,
                    ir_id: Some(ir_id),
                    span: n.span,
                    message: format!(
                        "{}: use NOTIFICATION-TYPE instead of TRAP-TYPE in SMIv2",
                        n.name
                    ),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

/// Warn about unreferenced type definitions.
fn check_type_unreferenced(ctx: &mut ResolverContext) {
    let mut referenced: Vec<std::collections::HashSet<String>> =
        vec![std::collections::HashSet::new(); ctx.modules.len()];

    for (m, refs) in ctx.modules.iter().zip(referenced.iter_mut()) {
        for def in &m.definitions {
            match def {
                ir::Definition::ObjectType(ot) => {
                    collect_type_refs(&ot.syntax, refs);
                }
                ir::Definition::TypeDef(td) => {
                    collect_type_refs(&td.syntax, refs);
                }
                ir::Definition::ModuleCompliance(comp) => {
                    for cm in &comp.modules {
                        for obj in &cm.objects {
                            if let Some(syntax) = &obj.syntax {
                                collect_type_refs(syntax, refs);
                            }
                            if let Some(syntax) = &obj.write_syntax {
                                collect_type_refs(syntax, refs);
                            }
                        }
                    }
                }
                ir::Definition::AgentCapabilities(cap) => {
                    for support in &cap.supports {
                        for variation in &support.variations {
                            if let Some(syntax) = &variation.syntax {
                                collect_type_refs(syntax, refs);
                            }
                            if let Some(syntax) = &variation.write_syntax {
                                collect_type_refs(syntax, refs);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        for import in &m.imports {
            for (source_idx, source_module) in ctx.modules.iter().enumerate() {
                if source_module.name == import.module {
                    referenced[source_idx].insert(import.symbol.clone());
                }
            }
        }
    }

    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def
                && !matches!(td.syntax, ir::TypeSyntax::Sequence { .. })
                && !referenced[ir_id.index()].contains(&td.name)
            {
                diags.push(Diag {
                    code: DiagCode::TypeUnreferenced,
                    ir_id: Some(ir_id),
                    span: td.span,
                    message: format!("{}: type defined but never referenced", td.name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

fn collect_type_refs(syntax: &ir::TypeSyntax, refs: &mut std::collections::HashSet<String>) {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => {
            refs.insert(name.clone());
        }
        ir::TypeSyntax::Constrained { base, .. } => {
            collect_type_refs(base, refs);
        }
        _ => {}
    }
}

/// Check that named number values are in ascending order.
fn check_named_number_ordering(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let (name, syntax, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, &ot.syntax, ot.span),
                ir::Definition::TypeDef(td) => (&td.name, &td.syntax, td.span),
                _ => continue,
            };

            collect_ordering_diags(&mut diags, ir_id, name, syntax, span);
        }
    }

    emit_all(ctx, diags);
}

fn collect_ordering_diags(
    diags: &mut Vec<Diag>,
    ir_id: IrModuleId,
    name: &str,
    syntax: &ir::TypeSyntax,
    span: Span,
) {
    match syntax {
        ir::TypeSyntax::IntegerEnum { named_numbers, .. } => {
            for i in 1..named_numbers.len() {
                if named_numbers[i].value < named_numbers[i - 1].value {
                    diags.push(Diag {
                        code: DiagCode::NamedNumbersAscending,
                        ir_id: Some(ir_id),
                        span,
                        message: format!("{}: named numbers should be in ascending order", name),
                    });
                    break;
                }
            }
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            for i in 1..named_bits.len() {
                if named_bits[i].position < named_bits[i - 1].position {
                    diags.push(Diag {
                        code: DiagCode::NamedNumbersAscending,
                        ir_id: Some(ir_id),
                        span,
                        message: format!("{}: bit positions should be in ascending order", name),
                    });
                    break;
                }
            }
        }
        ir::TypeSyntax::Constrained { base, .. } => {
            collect_ordering_diags(diags, ir_id, name, base, span);
        }
        _ => {}
    }
}

/// Validate range constraints.
fn check_range_constraints(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            match def {
                ir::Definition::TypeDef(td) => {
                    if matches!(td.syntax, ir::TypeSyntax::Sequence { .. }) {
                        continue;
                    }
                    let base = ctx
                        .module_symbol_to_type
                        .get(&ir_id)
                        .and_then(|syms| syms.get(&td.name))
                        .copied()
                        .map(|tid| ctx.mib.raw().type_(tid).effective_base(ctx.mib.types_slice()))
                        .and_then(|base| {
                            if base == BaseType::Unknown {
                                diagnostic_base_from_syntax(&td.syntax)
                            } else {
                                Some(base)
                            }
                        })
                        .or_else(|| diagnostic_base_from_syntax(&td.syntax));
                    collect_range_diags(&mut diags, ir_id, &td.name, &td.syntax, td.span, base);
                }
                ir::Definition::ObjectType(ot) => {
                    let base = ctx
                        .module_symbol_to_node
                        .get(&ir_id)
                        .and_then(|syms| syms.get(&ot.name))
                        .copied()
                        .and_then(|nid| ctx.mib.tree().get(nid).object)
                        .and_then(|oid| ctx.mib.raw().object(oid).typ)
                        .map(|tid| ctx.mib.raw().type_(tid).effective_base(ctx.mib.types_slice()));
                    collect_range_diags(&mut diags, ir_id, &ot.name, &ot.syntax, ot.span, base);
                }
                _ => {}
            }
        }
    }

    emit_all(ctx, diags);
}

fn diagnostic_base_from_syntax(syntax: &ir::TypeSyntax) -> Option<BaseType> {
    match syntax {
        ir::TypeSyntax::IntegerEnum { base, .. } => {
            if base.is_empty() {
                Some(BaseType::Integer32)
            } else {
                diagnostic_base_from_name(base)
            }
        }
        ir::TypeSyntax::Bits { .. } => Some(BaseType::Bits),
        ir::TypeSyntax::OctetString => Some(BaseType::OctetString),
        ir::TypeSyntax::ObjectIdentifier => Some(BaseType::ObjectIdentifier),
        ir::TypeSyntax::Constrained { base, .. } => diagnostic_base_from_syntax(base),
        ir::TypeSyntax::TypeRef { name, .. } => diagnostic_base_from_name(name),
        ir::TypeSyntax::Sequence { .. } | ir::TypeSyntax::SequenceOf { .. } => None,
    }
}

fn diagnostic_base_from_name(name: &str) -> Option<BaseType> {
    match super::types::base_type_from_name(name) {
        BaseType::Unknown => None,
        b => Some(b),
    }
}

fn collect_range_diags(
    diags: &mut Vec<Diag>,
    ir_id: IrModuleId,
    name: &str,
    syntax: &ir::TypeSyntax,
    span: Span,
    base: Option<BaseType>,
) {
    if let ir::TypeSyntax::Constrained { constraint, .. } = syntax {
        let (ranges, is_size) = match constraint {
            ir::Constraint::Size { ranges, .. } => (ranges, true),
            ir::Constraint::Range { ranges, .. } => (ranges, false),
        };

        if let Some(base) = base {
            // SIZE only applies to OCTET STRING and Opaque.
            if is_size && base != BaseType::OctetString && base != BaseType::Opaque {
                diags.push(Diag {
                    code: DiagCode::SizeIllegal,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{name:?}: SIZE constraint illegal for non-octet-string type"),
                });
                return;
            }

            // Value range only applies to numeric types.
            if !is_size && !is_numeric_base(base) {
                diags.push(Diag {
                    code: DiagCode::RangeIllegal,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{name:?}: range constraint illegal for non-numerical type"),
                });
                return;
            }

            // Counter types must not have range restrictions (RFC 2578).
            if !is_size && (base == BaseType::Counter32 || base == BaseType::Counter64) {
                diags.push(Diag {
                    code: DiagCode::CounterRangeIllegal,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{name:?}: range constraint illegal for Counter type"),
                });
                return;
            }

            // TimeTicks may not be sub-typed (RFC 2578 s7.1.8).
            if !is_size && base == BaseType::TimeTicks {
                diags.push(Diag {
                    code: DiagCode::TimeticksRangeIllegal,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{name:?}: range constraint illegal for TimeTicks type"),
                });
                return;
            }
        }

        let bounds = if is_size {
            Some((0i64, 65535i64))
        } else {
            base.and_then(basetype_bounds)
        };

        for (i, r) in ranges.iter().enumerate() {
            // Exchanged limits (min > max).
            if let Some(ref max) = r.max
                && range_value_gt(&r.min, max)
            {
                diags.push(Diag {
                    code: DiagCode::RangeExchanged,
                    ir_id: Some(ir_id),
                    span,
                    message: format!(
                        "{:?}: range {}..{} has exchanged limits",
                        name,
                        format_range_value(&r.min),
                        format_range_value(max)
                    ),
                });
            }

            // Bounds checking against basetype.
            if let Some((bmin, bmax)) = bounds {
                check_range_bound(diags, ir_id, span, name, &r.min, bmin, bmax, "lower");
                if let Some(ref max) = r.max {
                    check_range_bound(diags, ir_id, span, name, max, bmin, bmax, "upper");
                }
            }

            // Multi-range checks against previous range.
            if i > 0 {
                let prev = &ranges[i - 1];
                let prev_end = prev.max.as_ref().unwrap_or(&prev.min);
                // Ascending order: current min should be >= previous min.
                if range_value_gt(&prev.min, &r.min) {
                    diags.push(Diag {
                        code: DiagCode::RangeAscending,
                        ir_id: Some(ir_id),
                        span,
                        message: format!("{name:?}: ranges not in ascending order"),
                    });
                }
                // Overlap: current min should be > previous max.
                if !range_value_gt(&r.min, prev_end) {
                    diags.push(Diag {
                        code: DiagCode::RangeOverlap,
                        ir_id: Some(ir_id),
                        span,
                        message: format!(
                            "{:?}: range {} overlaps with {}",
                            name,
                            format_ir_range(r),
                            format_ir_range(prev)
                        ),
                    });
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn check_range_bound(
    diags: &mut Vec<Diag>,
    ir_id: IrModuleId,
    span: Span,
    name: &str,
    value: &ir::RangeValue,
    bounds_min: i64,
    bounds_max: i64,
    which: &str,
) {
    // MIN/MAX keywords are always valid.
    let v = match value {
        ir::RangeValue::Signed(v) => *v,
        ir::RangeValue::Unsigned(v) => {
            if *v > i64::MAX as u64 {
                // Value exceeds i64 range, definitely out of bounds for any basetype.
                diags.push(Diag {
                    code: DiagCode::RangeBounds,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{name:?}: range {which} bound {v} exceeds basetype"),
                });
                return;
            }
            *v as i64
        }
        ir::RangeValue::Min | ir::RangeValue::Max => return,
    };
    if v < bounds_min || v > bounds_max {
        diags.push(Diag {
            code: DiagCode::RangeBounds,
            ir_id: Some(ir_id),
            span,
            message: format!("{name:?}: range {which} bound {v} exceeds basetype"),
        });
    }
}

fn basetype_bounds(base: BaseType) -> Option<(i64, i64)> {
    match base {
        BaseType::Integer32 => Some((i32::MIN as i64, i32::MAX as i64)),
        BaseType::Unsigned32 | BaseType::Gauge32 | BaseType::TimeTicks | BaseType::Counter32 => {
            Some((0, u32::MAX as i64))
        }
        BaseType::Counter64 => Some((0, i64::MAX)),
        _ => None,
    }
}

fn is_numeric_base(base: BaseType) -> bool {
    basetype_bounds(base).is_some()
}

/// Flag plain type assignments in SMIv2 (should use TEXTUAL-CONVENTION).
fn check_type_assignment_smiv2(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def {
                if td.is_textual_convention {
                    continue;
                }
                // Skip SEQUENCE type assignments (table row definitions).
                if matches!(td.syntax, ir::TypeSyntax::Sequence { .. }) {
                    continue;
                }
                diags.push(Diag {
                    code: DiagCode::TypeAssignmentSMIv2,
                    ir_id: Some(ir_id),
                    span: td.span,
                    message: format!(
                        "{}: type assignment in SMIv2 should be a TEXTUAL-CONVENTION",
                        td.name
                    ),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

/// Flag TEXTUAL-CONVENTIONs derived from other TCs (RFC 2579 s3.5).
fn check_tc_nested(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let td = match def {
                ir::Definition::TypeDef(td) if td.is_textual_convention => td,
                _ => continue,
            };

            let type_id = match ctx
                .module_symbol_to_type
                .get(&ir_id)
                .and_then(|syms| syms.get(&td.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let t = ctx.mib.raw().type_(type_id);
            if let Some(parent_id) = t.parent() {
                let parent = ctx.mib.raw().type_(parent_id);
                if parent.is_textual_convention() {
                    diags.push(Diag {
                        code: DiagCode::TCNested,
                        ir_id: Some(ir_id),
                        span: td.span,
                        message: format!(
                            "{}: textual convention derived from textual convention {}",
                            td.name,
                            parent.name()
                        ),
                    });
                }
            }
        }
    }

    emit_all(ctx, diags);
}

/// Flag OBJECT-TYPE using Opaque in SMIv2 (RFC 2578 s7.1.3).
fn check_opaque_smiv2(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };

            let obj_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&ot.name))
                .copied()
                .and_then(|nid| ctx.mib.tree().get(nid).object)
            {
                Some(id) => id,
                None => continue,
            };
            let type_id = match ctx.mib.raw().object(obj_id).typ {
                Some(id) => id,
                None => continue,
            };

            let t = ctx.mib.raw().type_(type_id);
            if t.effective_base(ctx.mib.types_slice()) == BaseType::Opaque {
                diags.push(Diag {
                    code: DiagCode::OpaqueSMIv2,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!("{}: Opaque type should not be used in SMIv2", ot.name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate notification OID structure for SNMPv1 reverse mapping (RFC 2578 s8.5).
fn check_notification_reversibility(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            let n = match def {
                ir::Definition::Notification(n) if n.trap_info.is_none() => n,
                _ => continue,
            };

            let node_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&n.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let node = ctx.mib.tree().get(node_id);

            // Check last sub-id fits in i32.
            if node.arc > i32::MAX as u32 {
                diags.push(Diag {
                    code: DiagCode::NotifIdTooLarge,
                    ir_id: Some(ir_id),
                    span: n.span,
                    message: format!(
                        "last sub-identifier of notification {} is too large",
                        n.name
                    ),
                });
            }

            // Five well-known notifications predate the .0. convention.
            if is_exempt_notification(&m.name, &n.name) {
                continue;
            }

            // Parent's arc must be 0 for reverse mapping to SNMPv1 traps.
            let parent_id = match node.parent {
                Some(p) => p,
                None => continue,
            };
            let parent = ctx.mib.tree().get(parent_id);
            if parent.arc != 0 {
                diags.push(Diag {
                    code: DiagCode::NotifNotReversible,
                    ir_id: Some(ir_id),
                    span: n.span,
                    message: format!("notification {} is not reverse mappable", n.name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

fn is_exempt_notification(module_name: &str, notif_name: &str) -> bool {
    match module_name {
        "SNMPv2-MIB" => matches!(
            notif_name,
            "coldStart" | "warmStart" | "authenticationFailure"
        ),
        "IF-MIB" => matches!(notif_name, "linkDown" | "linkUp"),
        _ => false,
    }
}

/// Flag implicit OID tree nodes (unnamed internal nodes with children).
fn check_node_implicit(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    let root = ctx.mib.tree().root();
    let mut stack = vec![root];
    while let Some(nid) = stack.pop() {
        let node = ctx.mib.tree().get(nid);
        for &child_id in node.children().values() {
            stack.push(child_id);
        }

        if nid == root || node.kind != Kind::Internal {
            continue;
        }
        if !node.name.is_empty() || node.children().is_empty() {
            continue;
        }

        // Find module of first named child for attribution.
        let ir_id = node
            .children()
            .values()
            .filter_map(|&child| {
                let child_node = ctx.mib.tree().get(child);
                child_node
                    .module
                    .and_then(|mod_id| ctx.resolved_to_module.get(&mod_id).copied())
            })
            .next();

        let oid = ctx.mib.tree().oid_of(nid);
        diags.push(Diag {
            code: DiagCode::NodeImplicit,
            ir_id,
            span: Span::ZERO,
            message: format!("implicit node at OID {}", oid),
        });
    }

    emit_all(ctx, diags);
}

/// Flag identifiers within a module differing only in case.
fn check_identifier_case_match(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        // Group definitions by lowercased name, excluding SEQUENCE types.
        let mut by_lower: HashMap<String, Vec<(&str, Span)>> = HashMap::new();
        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def
                && matches!(td.syntax, ir::TypeSyntax::Sequence { .. })
            {
                continue;
            }
            let name = def.name();
            let span = def.span();
            by_lower
                .entry(name.to_lowercase())
                .or_default()
                .push((name, span));
        }

        for defs in by_lower.values() {
            if defs.len() < 2 {
                continue;
            }
            // Deduplicate by exact name.
            let mut seen = HashSet::new();
            let mut distinct: Vec<(&str, Span)> = Vec::new();
            for &(name, span) in defs {
                if seen.insert(name) {
                    distinct.push((name, span));
                }
            }
            if distinct.len() < 2 {
                continue;
            }
            let first_name = distinct[0].0;
            for &(name, span) in &distinct[1..] {
                diags.push(Diag {
                    code: DiagCode::IdentifierCaseMatch,
                    ir_id: Some(ir_id),
                    span,
                    message: format!("{}: differs from {} only in case", name, first_name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate status per SMI version across all definition types.
fn check_status_per_version(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let (name, status, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, ot.status, ot.span),
                ir::Definition::ObjectIdentity(oi) => (&oi.name, oi.status, oi.span),
                ir::Definition::Notification(n) if n.trap_info.is_none() => {
                    (&n.name, n.status, n.span)
                }
                ir::Definition::TypeDef(td) if td.is_textual_convention => {
                    (&td.name, td.status, td.span)
                }
                ir::Definition::ObjectGroup(g) => (&g.name, g.status, g.span),
                ir::Definition::NotificationGroup(g) => (&g.name, g.status, g.span),
                ir::Definition::ModuleCompliance(c) => (&c.name, c.status, c.span),
                ir::Definition::AgentCapabilities(c) => (&c.name, c.status, c.span),
                _ => continue,
            };

            match m.language {
                Language::SMIv1 => {
                    if status == Status::Current {
                        // "current" is technically SMIv2 but widely used in v1.
                        // Only flag if strict. The DiagCode severity handles this.
                        diags.push(Diag {
                            code: DiagCode::StatusInvalidSMIv1,
                            ir_id: Some(ir_id),
                            span,
                            message: format!("{:?}: invalid status current in SMIv1", name),
                        });
                    }
                }
                Language::SMIv2 => {
                    if status.is_smiv1() {
                        diags.push(Diag {
                            code: DiagCode::StatusInvalidSMIv2,
                            ir_id: Some(ir_id),
                            span,
                            message: format!("{:?}: invalid status {} in SMIv2", name, status),
                        });
                    }
                }
                _ => {}
            }

            // SMIv1 access per version (accessible-for-notify/read-create invalid).
            if let ir::Definition::ObjectType(ot) = def {
                if m.language == Language::SMIv1
                    && matches!(ot.access, Access::AccessibleForNotify | Access::ReadCreate)
                {
                    diags.push(Diag {
                        code: DiagCode::AccessInvalidSMIv1,
                        ir_id: Some(ir_id),
                        span: ot.access_span,
                        message: format!("{}: invalid access {} in SMIv1", ot.name, ot.access),
                    });
                }
                // Scalar must not be read-create.
                if let Some(node_id) = ctx
                    .module_symbol_to_node
                    .get(&ir_id)
                    .and_then(|syms| syms.get(&ot.name))
                    .copied()
                {
                    let kind = ctx.mib.tree().get(node_id).kind;
                    if kind == Kind::Scalar && ot.access == Access::ReadCreate {
                        diags.push(Diag {
                            code: DiagCode::ScalarNotCreatable,
                            ir_id: Some(ir_id),
                            span: ot.span,
                            message: format!("{:?}: scalar must not be read-create", ot.name),
                        });
                    }
                }
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate SEQUENCE fields match column definitions.
fn check_sequence_fields(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        // Find SEQUENCE type definitions in this module.
        let mut seq_types: HashMap<String, &[ir::SequenceField]> = HashMap::new();
        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def
                && let ir::TypeSyntax::Sequence { fields, .. } = &td.syntax
            {
                seq_types.insert(td.name.clone(), fields);
            }
        }

        // For each row object, check its SEQUENCE definition.
        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };

            let node_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&ot.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let node = ctx.mib.tree().get(node_id);
            if node.kind != Kind::Row {
                continue;
            }

            // The SEQUENCE type name is typically the same as the syntax type ref.
            let seq_name = match &ot.syntax {
                ir::TypeSyntax::TypeRef { name, .. } => name.as_str(),
                _ => continue,
            };

            let fields = match seq_types.get(seq_name) {
                Some(f) => *f,
                None => continue,
            };

            // Collect column names from child nodes.
            let column_names: HashSet<String> = node
                .children()
                .values()
                .map(|&child_id| ctx.mib.tree().get(child_id).name.clone())
                .filter(|n| !n.is_empty())
                .collect();

            // Check each SEQUENCE field has a matching column.
            for field in fields {
                if !column_names.contains(&field.name) {
                    diags.push(Diag {
                        code: DiagCode::SequenceNoColumn,
                        ir_id: Some(ir_id),
                        span: field.span,
                        message: format!(
                            "{}: SEQUENCE field {} has no matching column",
                            ot.name, field.name
                        ),
                    });
                }
            }

            // Check each column has a matching SEQUENCE field.
            let field_names: HashSet<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            for &child_id in node.children().values() {
                let child = ctx.mib.tree().get(child_id);
                if !child.name.is_empty() && !field_names.contains(child.name.as_str()) {
                    diags.push(Diag {
                        code: DiagCode::SequenceMissingColumn,
                        ir_id: Some(ir_id),
                        span: ot.span,
                        message: format!(
                            "column {:?} of row {:?} is not in SEQUENCE {:?}",
                            child.name, ot.name, seq_name
                        ),
                    });
                }
            }

            // Check SEQUENCE field order matches column arc order.
            let ordered_columns: Vec<&str> = node
                .children()
                .values()
                .map(|&child_id| ctx.mib.tree().get(child_id).name.as_str())
                .filter(|n| !n.is_empty())
                .collect();
            let field_order: Vec<&str> = fields
                .iter()
                .map(|f| f.name.as_str())
                .filter(|n| column_names.contains(*n))
                .collect();
            let col_order: Vec<&str> = ordered_columns
                .iter()
                .filter(|n| field_names.contains(**n))
                .copied()
                .collect();
            if field_order != col_order && field_order.len() == col_order.len() {
                diags.push(Diag {
                    code: DiagCode::SequenceOrder,
                    ir_id: Some(ir_id),
                    span: ot.span,
                    message: format!(
                        "{}: SEQUENCE field order does not match column order",
                        ot.name
                    ),
                });
            }

            // Check SEQUENCE field types match column types.
            let column_by_name: HashMap<&str, NodeId> = node
                .children()
                .values()
                .map(|&cid| (ctx.mib.tree().get(cid).name.as_str(), cid))
                .filter(|(n, _)| !n.is_empty())
                .collect();

            for field in fields {
                let col_node_id = match column_by_name.get(field.name.as_str()) {
                    Some(&id) => id,
                    None => continue,
                };
                let col_obj_id = match ctx.mib.tree().get(col_node_id).object {
                    Some(id) => id,
                    None => continue,
                };
                let col_type_id = match ctx.mib.raw().object(col_obj_id).typ {
                    Some(id) => id,
                    None => continue,
                };
                let field_type_name = sequence_field_type_name(&field.syntax);
                if field_type_name.is_empty() {
                    continue;
                }
                let col_type = ctx.mib.raw().type_(col_type_id);
                let col_type_name = col_type.name();
                let col_base = col_type.effective_base(ctx.mib.types_slice());
                if !sequence_types_compatible(&field_type_name, col_type_name, col_base) {
                    diags.push(Diag {
                        code: DiagCode::SequenceTypeMismatch,
                        ir_id: Some(ir_id),
                        span: field.span,
                        message: format!(
                            "SEQUENCE {:?} field {:?} type {:?} does not match column type {:?}",
                            seq_name, field.name, field_type_name, col_type_name
                        ),
                    });
                }
            }
        }
    }

    emit_all(ctx, diags);
}

fn check_group_membership(ctx: &mut ResolverContext) {
    #[derive(Default)]
    struct GroupInfo {
        has_object_group: bool,
        has_notification_group: bool,
        grouped_nodes: HashSet<NodeId>,
    }

    let mut module_groups: HashMap<ModuleId, GroupInfo> = HashMap::new();
    for (mid_idx, module) in ctx.mib.modules_slice().iter().enumerate() {
        if module.is_base() {
            continue;
        }
        let mid = ModuleId::new(mid_idx as u32);
        for &gid in module.groups() {
            let grp = ctx.mib.raw().group(gid);
            let info = module_groups.entry(mid).or_default();
            if grp.is_notification_group() {
                info.has_notification_group = true;
            } else {
                info.has_object_group = true;
            }
            info.grouped_nodes.extend(grp.members().iter().copied());
        }
    }

    let mut diags = Vec::new();
    let object_ids: Vec<ObjectId> = (0..ctx.mib.objects_slice().len())
        .map(|i| ObjectId::new(i as u32))
        .collect();
    for obj_id in object_ids {
        let obj = ctx.mib.raw().object(obj_id);
        let Some(module_id) = obj.module() else {
            continue;
        };
        let Some(node_id) = obj.node() else {
            continue;
        };
        let Some(info) = module_groups.get(&module_id) else {
            continue;
        };
        if !info.has_object_group {
            continue;
        }
        let kind = ctx.mib.tree().get(node_id).kind;
        if !matches!(kind, Kind::Scalar | Kind::Column) || obj.access() == Access::NotAccessible {
            continue;
        }
        if !info.grouped_nodes.contains(&node_id) {
            let ir_mod = ctx.resolved_to_module.get(&module_id).copied();
            diags.push(Diag {
                code: DiagCode::GroupMembership,
                ir_id: ir_mod,
                span: obj.span(),
                message: format!("{:?} is not in any OBJECT-GROUP", obj.name()),
            });
        }
    }

    let notif_ids: Vec<crate::mib::NotificationId> = (0..ctx.mib.notifications_slice().len())
        .map(|i| crate::mib::NotificationId::new(i as u32))
        .collect();
    for notif_id in notif_ids {
        let notif = ctx.mib.raw().notification(notif_id);
        let Some(module_id) = notif.module() else {
            continue;
        };
        let Some(node_id) = notif.node() else {
            continue;
        };
        let Some(info) = module_groups.get(&module_id) else {
            continue;
        };
        if !info.has_notification_group {
            continue;
        }
        if !info.grouped_nodes.contains(&node_id) {
            let ir_mod = ctx.resolved_to_module.get(&module_id).copied();
            diags.push(Diag {
                code: DiagCode::GroupMembership,
                ir_id: ir_mod,
                span: notif.span(),
                message: format!("{:?} is not in any NOTIFICATION-GROUP", notif.name()),
            });
        }
    }
    emit_all(ctx, diags);
}

fn check_group_member_locality(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();
    for (ir_id, m) in ctx.all_modules() {
        let local = ctx.module_symbol_to_node.get(&ir_id);
        for def in &m.definitions {
            let (span, members): (Span, &[String]) = match def {
                ir::Definition::ObjectGroup(g) => (g.span, &g.objects),
                ir::Definition::NotificationGroup(g) => (g.span, &g.notifications),
                _ => continue,
            };
            for member in members {
                let is_local = local.is_some_and(|syms| syms.contains_key(member));
                if !is_local {
                    diags.push(Diag {
                        code: DiagCode::ComplianceMemberNotLocal,
                        ir_id: Some(ir_id),
                        span,
                        message: format!(
                            "group member {:?} is not defined in module {:?}",
                            member, m.name
                        ),
                    });
                }
            }
        }
    }
    emit_all(ctx, diags);
}

fn check_compliance_structure(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();
    for (ir_id, m) in ctx.all_modules() {
        for def in &m.definitions {
            let comp = match def {
                ir::Definition::ModuleCompliance(c) => c,
                _ => continue,
            };
            for cm in &comp.modules {
                let mandatory: HashSet<&str> =
                    cm.mandatory_groups.iter().map(String::as_str).collect();
                let mut optional_seen = HashSet::new();
                for g in &cm.groups {
                    if mandatory.contains(g.group.as_str()) {
                        diags.push(Diag {
                            code: DiagCode::ComplianceGroupInvalid,
                            ir_id: Some(ir_id),
                            span: comp.span,
                            message: format!(
                                "group {:?} is both mandatory and optional in {:?}",
                                g.group, comp.name
                            ),
                        });
                    }
                    if !optional_seen.insert(g.group.as_str()) {
                        diags.push(Diag {
                            code: DiagCode::OptionalGroupExists,
                            ir_id: Some(ir_id),
                            span: comp.span,
                            message: format!(
                                "duplicate optional group {:?} in {:?}",
                                g.group, comp.name
                            ),
                        });
                    }
                }

                let mut refinement_seen = HashSet::new();
                for o in &cm.objects {
                    if !refinement_seen.insert(o.object.as_str()) {
                        diags.push(Diag {
                            code: DiagCode::RefinementExists,
                            ir_id: Some(ir_id),
                            span: comp.span,
                            message: format!(
                                "duplicate refinement for {:?} in {:?}",
                                o.object, comp.name
                            ),
                        });
                    }
                }

                if cm.objects.is_empty() {
                    continue;
                }
                let mut member_names = HashSet::new();
                for group in &cm.mandatory_groups {
                    collect_compliance_group_member_names(ctx, ir_id, cm, group, &mut member_names);
                }
                for group in &cm.groups {
                    collect_compliance_group_member_names(
                        ctx,
                        ir_id,
                        cm,
                        &group.group,
                        &mut member_names,
                    );
                }
                for o in &cm.objects {
                    if !member_names.contains(o.object.as_str()) {
                        diags.push(Diag {
                            code: DiagCode::RefinementNotListed,
                            ir_id: Some(ir_id),
                            span: comp.span,
                            message: format!(
                                "refined object {:?} not in any mandatory or optional group of {:?}",
                                o.object, comp.name
                            ),
                        });
                    }
                }
            }
        }
    }
    emit_all(ctx, diags);
}

fn collect_compliance_group_member_names(
    ctx: &ResolverContext,
    from_ir: IrModuleId,
    cm: &ir::ComplianceModule,
    group_name: &str,
    out: &mut HashSet<String>,
) {
    let node = if cm.module_name.is_empty() {
        ctx.lookup_node_for_module(from_ir, group_name)
            .map(|(n, _)| n)
    } else {
        ctx.lookup_node_in_module(&cm.module_name, group_name)
    };
    let Some(node_id) = node else {
        return;
    };
    let Some(group_id) = ctx.mib.tree().get(node_id).group else {
        return;
    };
    for &member_node in ctx.mib.raw().group(group_id).members() {
        let name = ctx.mib.tree().get(member_node).name().to_string();
        if !name.is_empty() {
            out.insert(name);
        }
    }
}

fn check_module_identity_registration(ctx: &mut ResolverContext) {
    const MGMT: &[u32] = &[1, 3, 6, 1, 2];
    const MIB2: &[u32] = &[1, 3, 6, 1, 2, 1];
    const TRANSMISSION: &[u32] = &[1, 3, 6, 1, 2, 1, 10];
    const SNMP_MODULES: &[u32] = &[1, 3, 6, 1, 6, 3];

    let mut diags = Vec::new();
    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let mi = match def {
                ir::Definition::ModuleIdentity(mi) => mi,
                _ => continue,
            };
            let Some((node, _)) = ctx.lookup_node_for_module(ir_id, &mi.name) else {
                continue;
            };
            let oid = ctx.mib.tree().oid_of(node);
            if oid.len() < 2 {
                diags.push(Diag {
                    code: DiagCode::ModuleIdentityReg,
                    ir_id: Some(ir_id),
                    span: mi.span,
                    message: format!(
                        "{:?}: MODULE-IDENTITY OID too short for valid registration",
                        mi.name
                    ),
                });
                continue;
            }
            if !oid.starts_with(MGMT) {
                continue;
            }
            if oid.starts_with(MIB2)
                || oid.starts_with(TRANSMISSION)
                || oid.starts_with(SNMP_MODULES)
            {
                continue;
            }
            diags.push(Diag {
                code: DiagCode::ModuleIdentityReg,
                ir_id: Some(ir_id),
                span: mi.span,
                message: format!(
                    "{:?}: MODULE-IDENTITY registered under uncontrolled mgmt OID {}",
                    mi.name, oid
                ),
            });
        }
    }
    emit_all(ctx, diags);
}

fn check_row_status_defaults(ctx: &mut ResolverContext) {
    let Some(row_status_type) = ctx.mib.type_by_name("RowStatus") else {
        return;
    };
    let row_status_actions: HashMap<i64, &str> =
        HashMap::from([(4, "createAndGo"), (5, "createAndWait"), (6, "destroy")]);

    let mut diags = Vec::new();
    let object_ids: Vec<ObjectId> = (0..ctx.mib.objects_slice().len())
        .map(|i| ObjectId::new(i as u32))
        .collect();
    for obj_id in object_ids {
        let obj = ctx.mib.raw().object(obj_id);
        let Some(type_id) = obj.type_id() else {
            continue;
        };
        if !is_derived_from_type(ctx, type_id, row_status_type) {
            continue;
        }

        let Some(module_id) = obj.module() else {
            continue;
        };
        let Some(ir_mod) = ctx.resolved_to_module.get(&module_id).copied() else {
            continue;
        };
        let lang = ctx.mib.raw().module(module_id).language();
        let access = obj.access();
        if lang == Language::SMIv2 && access != Access::ReadCreate {
            diags.push(Diag {
                code: DiagCode::RowStatusAccess,
                ir_id: Some(ir_mod),
                span: obj.span(),
                message: format!(
                    "{:?}: RowStatus should have MAX-ACCESS read-create, has {}",
                    obj.name(),
                    access
                ),
            });
        } else if lang == Language::SMIv1 && access != Access::ReadWrite {
            diags.push(Diag {
                code: DiagCode::RowStatusAccess,
                ir_id: Some(ir_mod),
                span: obj.span(),
                message: format!(
                    "{:?}: RowStatus should have ACCESS read-write, has {}",
                    obj.name(),
                    access
                ),
            });
        }

        let Some(dv) = obj.default_value() else {
            continue;
        };
        let Some(v) = defval_as_i64(dv, &row_status_actions) else {
            continue;
        };
        if let Some(name) = row_status_actions.get(&v) {
            diags.push(Diag {
                code: DiagCode::RowStatusDefault,
                ir_id: Some(ir_mod),
                span: obj.span(),
                message: format!(
                    "{:?}: RowStatus DEFVAL {}({}) is an action value, must be active(1), notInService(2), or notReady(3)",
                    obj.name(),
                    name,
                    v
                ),
            });
        }
    }
    emit_all(ctx, diags);
}

fn check_storage_type_defaults(ctx: &mut ResolverContext) {
    let Some(storage_type) = ctx.mib.type_by_name("StorageType") else {
        return;
    };
    let illegal_values: HashMap<i64, &str> = HashMap::from([(4, "permanent"), (5, "readOnly")]);
    let mut diags = Vec::new();
    let object_ids: Vec<ObjectId> = (0..ctx.mib.objects_slice().len())
        .map(|i| ObjectId::new(i as u32))
        .collect();
    for obj_id in object_ids {
        let obj = ctx.mib.raw().object(obj_id);
        let Some(type_id) = obj.type_id() else {
            continue;
        };
        if !is_derived_from_type(ctx, type_id, storage_type) {
            continue;
        }
        let Some(module_id) = obj.module() else {
            continue;
        };
        let Some(ir_mod) = ctx.resolved_to_module.get(&module_id).copied() else {
            continue;
        };
        let Some(dv) = obj.default_value() else {
            continue;
        };
        let Some(v) = defval_as_i64(dv, &illegal_values) else {
            continue;
        };
        if let Some(name) = illegal_values.get(&v) {
            diags.push(Diag {
                code: DiagCode::StorageTypeDefault,
                ir_id: Some(ir_mod),
                span: obj.span(),
                message: format!(
                    "{:?}: StorageType DEFVAL {}({}) is not a valid default, must be other(1), volatile(2), or nonVolatile(3)",
                    obj.name(),
                    name,
                    v
                ),
            });
        }
    }
    emit_all(ctx, diags);
}

fn defval_as_i64(dv: &crate::mib::types::DefVal, label_values: &HashMap<i64, &str>) -> Option<i64> {
    use crate::mib::types::DefValValue;
    match &dv.value {
        DefValValue::Int(v) => Some(*v),
        DefValValue::Uint(v) => i64::try_from(*v).ok(),
        DefValValue::Enum(label) => label_values
            .iter()
            .find_map(|(value, name)| (*name == label.as_str()).then_some(*value)),
        _ => None,
    }
}

fn check_taddress_tdomain(ctx: &mut ResolverContext) {
    let Some(t_address) = ctx.mib.type_by_name("TAddress") else {
        return;
    };
    let Some(t_domain) = ctx.mib.type_by_name("TDomain") else {
        return;
    };

    struct Check {
        ir_mod: Option<IrModuleId>,
        span: Span,
        name: String,
    }
    let mut checks = Vec::new();

    let object_ids: Vec<ObjectId> = (0..ctx.mib.objects_slice().len())
        .map(|i| ObjectId::new(i as u32))
        .collect();

    for oid in object_ids {
        let obj = ctx.mib.raw().object(oid);
        let Some(type_id) = obj.type_id() else {
            continue;
        };
        let Some(node_id) = obj.node() else {
            continue;
        };
        if ctx.mib.tree().get(node_id).kind != Kind::Column {
            continue;
        }
        if !is_derived_from_type(ctx, type_id, t_address) {
            continue;
        }
        let Some(row_id) = row_object_for_column(ctx, node_id) else {
            continue;
        };
        let has_sibling = row_column_objects(ctx, row_id).iter().any(|&col| {
            ctx.mib
                .raw()
                .object(col)
                .type_id()
                .is_some_and(|ct| is_derived_from_type(ctx, ct, t_domain))
        });
        if !has_sibling {
            checks.push(Check {
                ir_mod: obj
                    .module()
                    .and_then(|m| ctx.resolved_to_module.get(&m).copied()),
                span: obj.span(),
                name: obj.name().to_string(),
            });
        }
    }

    for check in checks {
        ctx.emit_diagnostic(
            DiagCode::TAddressTDomain,
            check.ir_mod,
            check.span,
            format!(
                "{:?}: TAddress column has no sibling with TDomain type",
                check.name
            ),
        );
    }
}

fn check_inet_address_pairing(ctx: &mut ResolverContext) {
    check_address_type_pairing(
        ctx,
        &AddressPairingConfig {
            module_name: "INET-ADDRESS-MIB",
            address_type: "InetAddress",
            address_type_type: "InetAddressType",
            specific_types: &[
                "InetAddressIPv4",
                "InetAddressIPv6",
                "InetAddressIPv4z",
                "InetAddressIPv6z",
                "InetAddressDNS",
            ],
            diag_pairing: DiagCode::InetAddressPairing,
            diag_subtyped: DiagCode::InetAddressTypeSubtyped,
            diag_specific: DiagCode::InetAddressSpecific,
        },
    );
}

fn check_transport_address_pairing(ctx: &mut ResolverContext) {
    check_address_type_pairing(
        ctx,
        &AddressPairingConfig {
            module_name: "TRANSPORT-ADDRESS-MIB",
            address_type: "TransportAddress",
            address_type_type: "TransportAddressType",
            specific_types: &[
                "TransportAddressIPv4",
                "TransportAddressIPv6",
                "TransportAddressIPv4z",
                "TransportAddressIPv6z",
                "TransportAddressLocal",
                "TransportAddressDns",
            ],
            diag_pairing: DiagCode::TransportAddressPairing,
            diag_subtyped: DiagCode::TransportAddressTypeSubtyped,
            diag_specific: DiagCode::TransportAddressSpecific,
        },
    );
}

struct AddressPairingConfig<'a> {
    module_name: &'a str,
    address_type: &'a str,
    address_type_type: &'a str,
    specific_types: &'a [&'a str],
    diag_pairing: DiagCode,
    diag_subtyped: DiagCode,
    diag_specific: DiagCode,
}

/// Implements three related checks for address/address-type pairing patterns:
/// - Pairing: address column should have a sibling address-type column
/// - Subtyped: address-type with enum refinement needs correspondingly constrained address sibling
/// - Specific: specific address variants should not be used when generic type is appropriate
fn check_address_type_pairing(ctx: &mut ResolverContext, cfg: &AddressPairingConfig) {
    let Some(addr_type_id) = lookup_type_in_named_module(ctx, cfg.module_name, cfg.address_type)
    else {
        return;
    };
    let Some(addr_type_type_id) =
        lookup_type_in_named_module(ctx, cfg.module_name, cfg.address_type_type)
    else {
        return;
    };

    // Resolve specific variant types.
    let specific_type_ids: Vec<TypeId> = cfg
        .specific_types
        .iter()
        .filter_map(|name| lookup_type_in_named_module(ctx, cfg.module_name, name))
        .collect();

    // Collect check info before emitting diagnostics.
    struct PairingCheck {
        ir_mod: Option<IrModuleId>,
        span: Span,
        name: String,
        check: PairingCheckKind,
    }
    enum PairingCheckKind {
        MissingSibling,
        Subtyped { sibling_name: String },
        Specific { variant_name: String },
    }

    let mut checks: Vec<PairingCheck> = Vec::new();

    // Build IR lookup for object syntax (needed for subtyped/SIZE checks).
    let mut obj_syntax_map: HashMap<(IrModuleId, String), &ir::TypeSyntax> = HashMap::new();
    for (ir_id, m) in ctx.all_modules() {
        for def in &m.definitions {
            if let ir::Definition::ObjectType(ot) = def {
                obj_syntax_map.insert((ir_id, ot.name.clone()), &ot.syntax);
            }
        }
    }

    let object_ids: Vec<ObjectId> = (0..ctx.mib.objects_slice().len())
        .map(|i| ObjectId::new(i as u32))
        .collect();

    for oid in &object_ids {
        let obj = ctx.mib.raw().object(*oid);
        let Some(type_id) = obj.type_id() else {
            continue;
        };
        let Some(node_id) = obj.node() else {
            continue;
        };
        if ctx.mib.tree().get(node_id).kind != Kind::Column {
            continue;
        }
        let ir_mod = obj
            .module()
            .and_then(|m| ctx.resolved_to_module.get(&m).copied());
        let obj_name = obj.name().to_string();
        let obj_span = obj.span();

        // Check 1: address column without address-type sibling.
        if is_derived_from_type(ctx, type_id, addr_type_id) {
            if let Some(row_id) = row_object_for_column(ctx, node_id) {
                let has_sibling = row_column_objects(ctx, row_id).iter().any(|&col| {
                    ctx.mib
                        .raw()
                        .object(col)
                        .type_id()
                        .is_some_and(|ct| is_derived_from_type(ctx, ct, addr_type_type_id))
                });
                if !has_sibling {
                    checks.push(PairingCheck {
                        ir_mod,
                        span: obj_span,
                        name: obj_name,
                        check: PairingCheckKind::MissingSibling,
                    });
                }
            }
            continue;
        }

        // Check 2: address-type column with enum refinement but address sibling lacks SIZE.
        if is_derived_from_type(ctx, type_id, addr_type_type_id) {
            // Only check if the OBJECT-TYPE SYNTAX has explicit enum refinement.
            let has_enum_syntax = ir_mod.is_some_and(|ir_id| {
                obj_syntax_map
                    .get(&(ir_id, obj_name.clone()))
                    .is_some_and(|s| matches!(s, ir::TypeSyntax::IntegerEnum { .. }))
            });
            if has_enum_syntax && let Some(row_id) = row_object_for_column(ctx, node_id) {
                for col in row_column_objects(ctx, row_id) {
                    let col_obj = ctx.mib.raw().object(col);
                    let Some(col_type) = col_obj.type_id() else {
                        continue;
                    };
                    if !is_derived_from_type(ctx, col_type, addr_type_id) {
                        continue;
                    }
                    // Check whether the sibling has an explicit SIZE constraint.
                    let col_name = col_obj.name().to_string();
                    let has_size = ir_mod.is_some_and(|ir_id| {
                        obj_syntax_map
                            .get(&(ir_id, col_name.clone()))
                            .is_some_and(|s| {
                                matches!(
                                    s,
                                    ir::TypeSyntax::Constrained {
                                        constraint: ir::Constraint::Size { .. },
                                        ..
                                    }
                                )
                            })
                    });
                    if !has_size {
                        checks.push(PairingCheck {
                            ir_mod,
                            span: obj_span,
                            name: obj_name.clone(),
                            check: PairingCheckKind::Subtyped {
                                sibling_name: col_name,
                            },
                        });
                    }
                    break;
                }
            }
            continue;
        }

        // Check 3: specific variant used instead of generic address type.
        for &specific_id in &specific_type_ids {
            if is_derived_from_type(ctx, type_id, specific_id) {
                let variant_name = ctx.mib.raw().type_(specific_id).name().to_string();
                checks.push(PairingCheck {
                    ir_mod,
                    span: obj_span,
                    name: obj_name.clone(),
                    check: PairingCheckKind::Specific { variant_name },
                });
                break;
            }
        }
    }

    for check in checks {
        match check.check {
            PairingCheckKind::MissingSibling => {
                ctx.emit_diagnostic(
                    cfg.diag_pairing,
                    check.ir_mod,
                    check.span,
                    format!(
                        "{:?}: {} column has no sibling with {} type",
                        check.name, cfg.address_type, cfg.address_type_type
                    ),
                );
            }
            PairingCheckKind::Subtyped { sibling_name } => {
                ctx.emit_diagnostic(
                    cfg.diag_subtyped,
                    check.ir_mod,
                    check.span,
                    format!(
                        "{:?}: {} is subtyped but sibling {:?} ({}) has no SIZE constraint",
                        check.name, cfg.address_type_type, sibling_name, cfg.address_type
                    ),
                );
            }
            PairingCheckKind::Specific { variant_name } => {
                ctx.emit_diagnostic(
                    cfg.diag_specific,
                    check.ir_mod,
                    check.span,
                    format!(
                        "{:?}: {} is a specific variant, use {} with {}",
                        check.name, variant_name, cfg.address_type, cfg.address_type_type
                    ),
                );
            }
        }
    }
}

fn lookup_type_in_named_module(
    ctx: &ResolverContext,
    module_name: &str,
    type_name: &str,
) -> Option<TypeId> {
    let ir_mods = ctx.module_index.get(module_name)?;
    for &ir in ir_mods {
        if let Some(tid) = ctx
            .module_symbol_to_type
            .get(&ir)
            .and_then(|syms| syms.get(type_name))
            .copied()
        {
            return Some(tid);
        }
    }
    None
}

fn row_object_for_column(ctx: &ResolverContext, column_node: NodeId) -> Option<ObjectId> {
    let row_node = ctx.mib.tree().get(column_node).parent()?;
    if ctx.mib.tree().get(row_node).kind != Kind::Row {
        return None;
    }
    ctx.mib.tree().get(row_node).object()
}

fn row_column_objects(ctx: &ResolverContext, row_obj: ObjectId) -> Vec<ObjectId> {
    let Some(row_node) = ctx.mib.raw().object(row_obj).node() else {
        return Vec::new();
    };
    ctx.mib
        .tree()
        .get(row_node)
        .children()
        .values()
        .filter_map(|&nid| {
            let n = ctx.mib.tree().get(nid);
            (n.kind == Kind::Column).then_some(n.object()).flatten()
        })
        .collect()
}

fn is_derived_from_type(ctx: &ResolverContext, type_id: TypeId, target: TypeId) -> bool {
    let mut current = Some(type_id);
    let mut depth = 0usize;
    while let Some(tid) = current {
        if depth > 1000 {
            break;
        }
        if tid == target {
            return true;
        }
        current = ctx.mib.raw().type_(tid).parent();
        depth += 1;
    }
    false
}

fn sequence_field_type_name(syntax: &ir::TypeSyntax) -> String {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => name.clone(),
        ir::TypeSyntax::IntegerEnum { .. } => "INTEGER".to_string(),
        ir::TypeSyntax::Bits { .. } => "BITS".to_string(),
        ir::TypeSyntax::OctetString => "OCTET STRING".to_string(),
        ir::TypeSyntax::ObjectIdentifier => "OBJECT IDENTIFIER".to_string(),
        ir::TypeSyntax::Constrained { base, .. } => sequence_field_type_name(base),
        _ => String::new(),
    }
}

fn normalize_type_name(name: &str) -> &str {
    match name {
        "Counter" => "Counter32",
        "Gauge" => "Gauge32",
        "INTEGER" => "Integer32",
        "NetworkAddress" => "IpAddress",
        _ => name,
    }
}

fn sequence_types_compatible(field_type: &str, col_type: &str, col_base: BaseType) -> bool {
    if field_type == col_type {
        return true;
    }
    let field_norm = normalize_type_name(field_type);
    let col_norm = normalize_type_name(col_type);
    if field_norm == col_norm {
        return true;
    }
    // INTEGER/Integer32 in SEQUENCE is compatible with Integer32-based columns (covers enums).
    if field_norm == "Integer32" && col_base == BaseType::Integer32 {
        return true;
    }
    // OCTET STRING/BITS in SEQUENCE is compatible with BITS-based columns.
    if (field_type == "OCTET STRING" || field_type == "BITS") && col_base == BaseType::Bits {
        return true;
    }
    false
}

// --- DEFVAL validation ---

/// Validate DEFVAL values against the object's type.
fn check_defval_constraints(ctx: &mut ResolverContext) {
    use crate::mib::types::DefValValue;

    // Collect all info we need before mutating ctx.
    struct DefvalCheck {
        ir_mod: Option<IrModuleId>,
        span: Span,
        name: String,
        base: BaseType,
        dv_value: DefValValue,
        ranges: Vec<crate::mib::types::Range>,
        enums: Vec<crate::mib::types::NamedValue>,
        bits: Vec<crate::mib::types::NamedValue>,
    }

    let mut checks = Vec::new();

    for i in 0..ctx.mib.objects_slice().len() {
        let obj_id = ObjectId::new(i as u32);
        let obj = ctx.mib.raw().object(obj_id);
        let dv = match obj.default_value() {
            Some(dv) => dv,
            None => continue,
        };
        let type_id = match obj.type_id() {
            Some(t) => t,
            None => continue,
        };
        let t = ctx.mib.raw().type_(type_id);
        let base = t.effective_base(ctx.mib.types_slice());
        let module_id = obj.module();
        let ir_mod = module_id.and_then(|m| ctx.resolved_to_module.get(&m).copied());

        checks.push(DefvalCheck {
            ir_mod,
            span: obj.span(),
            name: obj.name().to_string(),
            base,
            dv_value: dv.value.clone(),
            ranges: obj.effective_ranges().to_vec(),
            enums: obj.effective_enums().to_vec(),
            bits: obj.effective_bits().to_vec(),
        });
    }

    for check in checks {
        // Counter32 and Counter64 must not have DEFVAL.
        if check.base == BaseType::Counter32 || check.base == BaseType::Counter64 {
            ctx.emit_diagnostic(
                DiagCode::CounterDefvalIllegal,
                check.ir_mod,
                check.span,
                format!("{:?}: DEFVAL not allowed for counter type", check.name),
            );
            continue;
        }

        match &check.dv_value {
            DefValValue::Int(v) => {
                check_defval_numeric(
                    ctx,
                    check.ir_mod,
                    check.span,
                    &check.name,
                    *v,
                    check.base,
                    &check.ranges,
                    &check.enums,
                );
            }
            DefValValue::Uint(uv) => {
                check_defval_unsigned(
                    ctx,
                    check.ir_mod,
                    check.span,
                    &check.name,
                    *uv,
                    check.base,
                    &check.ranges,
                    &check.enums,
                );
            }
            DefValValue::Enum(label) => {
                if !check.enums.is_empty() && !check.enums.iter().any(|e| e.label == *label) {
                    ctx.emit_diagnostic(
                        DiagCode::DefvalEnum,
                        check.ir_mod,
                        check.span,
                        format!(
                            "{:?}: DEFVAL enum label {:?} not defined in type",
                            check.name, label
                        ),
                    );
                }
            }
            DefValValue::Bits(labels) => {
                for label in labels {
                    if !check.bits.iter().any(|b| b.label == *label) {
                        ctx.emit_diagnostic(
                            DiagCode::DefvalBits,
                            check.ir_mod,
                            check.span,
                            format!(
                                "{:?}: DEFVAL BITS label {:?} not defined in type",
                                check.name, label
                            ),
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn check_defval_numeric(
    ctx: &mut ResolverContext,
    ir_mod: Option<IrModuleId>,
    span: Span,
    name: &str,
    v: i64,
    base: BaseType,
    ranges: &[crate::mib::types::Range],
    enums: &[crate::mib::types::NamedValue],
) {
    // Check basetype limits.
    match base {
        BaseType::Integer32 => {
            if v < i32::MIN as i64 || v > i32::MAX as i64 {
                ctx.emit_diagnostic(
                    DiagCode::DefvalBasetype,
                    ir_mod,
                    span,
                    format!("{name:?}: DEFVAL {v} exceeds Integer32 range"),
                );
            }
        }
        BaseType::Unsigned32 | BaseType::Gauge32 | BaseType::TimeTicks => {
            if v < 0 || v > u32::MAX as i64 {
                ctx.emit_diagnostic(
                    DiagCode::DefvalBasetype,
                    ir_mod,
                    span,
                    format!("{name:?}: DEFVAL {v} exceeds unsigned32 range"),
                );
            }
        }
        _ => {}
    }
    // Check RANGE constraints.
    if !ranges.is_empty() && !value_in_ranges(v, ranges) {
        ctx.emit_diagnostic(
            DiagCode::DefvalRange,
            ir_mod,
            span,
            format!("{name:?}: DEFVAL {v} outside RANGE constraint"),
        );
    }
    // Check enum membership.
    if !enums.is_empty() && !enums.iter().any(|e| e.value == v) {
        ctx.emit_diagnostic(
            DiagCode::DefvalEnum,
            ir_mod,
            span,
            format!("{name:?}: DEFVAL {v} does not match any enumeration value"),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn check_defval_unsigned(
    ctx: &mut ResolverContext,
    ir_mod: Option<IrModuleId>,
    span: Span,
    name: &str,
    v: u64,
    base: BaseType,
    ranges: &[crate::mib::types::Range],
    enums: &[crate::mib::types::NamedValue],
) {
    match base {
        BaseType::Integer32 => {
            if v > i32::MAX as u64 {
                ctx.emit_diagnostic(
                    DiagCode::DefvalBasetype,
                    ir_mod,
                    span,
                    format!("{name:?}: DEFVAL {v} exceeds Integer32 range"),
                );
            }
        }
        BaseType::Unsigned32 | BaseType::Gauge32 | BaseType::TimeTicks => {
            if v > u32::MAX as u64 {
                ctx.emit_diagnostic(
                    DiagCode::DefvalBasetype,
                    ir_mod,
                    span,
                    format!("{name:?}: DEFVAL {v} exceeds unsigned32 range"),
                );
            }
        }
        _ => {}
    }
    if !ranges.is_empty() && v <= i64::MAX as u64 {
        let in_range = ranges.iter().any(|r| {
            if r.max < 0 {
                return false;
            }
            let min = if r.min > 0 { r.min as u64 } else { 0 };
            v >= min && v <= r.max as u64
        });
        if !in_range {
            ctx.emit_diagnostic(
                DiagCode::DefvalRange,
                ir_mod,
                span,
                format!("{name:?}: DEFVAL {v} outside RANGE constraint"),
            );
        }
    }
    if !enums.is_empty() {
        let found = enums.iter().any(|e| e.value >= 0 && e.value as u64 == v);
        if !found {
            ctx.emit_diagnostic(
                DiagCode::DefvalEnum,
                ir_mod,
                span,
                format!("{name:?}: DEFVAL {v} does not match any enumeration value"),
            );
        }
    }
}

fn value_in_ranges(v: i64, ranges: &[crate::mib::types::Range]) -> bool {
    ranges.iter().any(|r| v >= r.min && v <= r.max)
}

// --- Index validation ---

fn check_index_constraints(ctx: &mut ResolverContext) {
    // Collect data first, then emit diagnostics.
    let mut diags = Vec::new();
    let mut oid_length_check_ids: Vec<ObjectId> = Vec::new();

    for i in 0..ctx.mib.objects_slice().len() {
        let obj_id = ObjectId::new(i as u32);
        let obj = ctx.mib.raw().object(obj_id);
        let index = obj.index();
        if index.is_empty() {
            continue;
        }

        let module_id = obj.module();
        let ir_mod = module_id.and_then(|m| ctx.resolved_to_module.get(&m).copied());
        let lang = module_id
            .map(|m| ctx.mib.raw().module(m).language())
            .unwrap_or(Language::Unknown);
        let span = obj.span();
        let obj_name = obj.name().to_string();

        for entry in index {
            let idx_obj_id = match entry.object {
                Some(id) => id,
                None => continue,
            };

            let idx_obj = ctx.mib.raw().object(idx_obj_id);
            let idx_name = idx_obj.name().to_string();

            // INDEX column access checks.
            match lang {
                Language::SMIv2 => {
                    if idx_obj.access() != Access::NotAccessible {
                        diags.push(Diag {
                            code: DiagCode::IndexAccessible,
                            ir_id: ir_mod,
                            span,
                            message: format!(
                                "INDEX {:?} of {:?} should be not-accessible in SMIv2",
                                idx_name, obj_name
                            ),
                        });
                    }
                }
                Language::SMIv1 => {
                    if idx_obj.access() == Access::NotAccessible {
                        diags.push(Diag {
                            code: DiagCode::IndexNotAccessible,
                            ir_id: ir_mod,
                            span,
                            message: format!(
                                "INDEX {:?} of {:?} should be accessible in SMIv1",
                                idx_name, obj_name
                            ),
                        });
                    }
                }
                _ => {}
            }

            // INDEX elements should not have DEFVAL.
            if idx_obj.default_value().is_some() {
                diags.push(Diag {
                    code: DiagCode::IndexDefval,
                    ir_id: ir_mod,
                    span,
                    message: format!("INDEX {:?} of {:?} has a DEFVAL", idx_name, obj_name),
                });
            }

            let type_id = match idx_obj.type_id() {
                Some(t) => t,
                None => continue,
            };
            let t = ctx.mib.raw().type_(type_id);
            let base = t.effective_base(ctx.mib.types_slice());

            if base == BaseType::Counter32 {
                diags.push(Diag {
                    code: DiagCode::IndexCounterIllegal,
                    ir_id: ir_mod,
                    span,
                    message: format!(
                        "INDEX {:?} of {:?} has counter base type",
                        idx_name, obj_name
                    ),
                });
            } else if !is_legal_index_basetype(base) {
                diags.push(Diag {
                    code: DiagCode::IndexIllegalBasetype,
                    ir_id: ir_mod,
                    span,
                    message: format!(
                        "INDEX {:?} of {:?} has illegal base type {:?}",
                        idx_name, obj_name, base
                    ),
                });
                continue;
            }

            // OCTET STRING/Opaque index elements must have SIZE.
            if base == BaseType::OctetString || base == BaseType::Opaque {
                if idx_obj.effective_sizes().is_empty() {
                    diags.push(Diag {
                        code: DiagCode::IndexElementNoSize,
                        ir_id: ir_mod,
                        span,
                        message: format!(
                            "INDEX {:?} of {:?} has no SIZE restriction",
                            idx_name, obj_name
                        ),
                    });
                }
                continue;
            }

            if base != BaseType::Integer32 {
                continue;
            }

            let ranges = idx_obj.effective_ranges();
            let enums = idx_obj.effective_enums();

            // Enum-valued indexes: check for negative enum values.
            if !enums.is_empty() {
                for e in enums {
                    if e.value < 0 {
                        diags.push(Diag {
                            code: DiagCode::IndexNegativeRange,
                            ir_id: ir_mod,
                            span,
                            message: format!(
                                "INDEX {:?} of {:?} has negative enumeration value {:?}",
                                idx_name, obj_name, e.label
                            ),
                        });
                        break;
                    }
                }
                continue;
            }

            // No range restriction on an integer index.
            if ranges.is_empty() {
                diags.push(Diag {
                    code: DiagCode::IndexIntegerNoRange,
                    ir_id: ir_mod,
                    span,
                    message: format!(
                        "INDEX {:?} of {:?} has no range restriction",
                        idx_name, obj_name
                    ),
                });
                continue;
            }

            // Range includes negative values.
            for r in ranges {
                if r.min < 0 {
                    diags.push(Diag {
                        code: DiagCode::IndexNegativeRange,
                        ir_id: ir_mod,
                        span,
                        message: format!(
                            "INDEX {:?} of {:?} has range permitting negative values",
                            idx_name, obj_name
                        ),
                    });
                    break;
                }
            }
        }

        oid_length_check_ids.push(obj_id);
    }

    emit_all(ctx, diags);

    // Check total index OID length against the 128 sub-identifier limit.
    for obj_id in oid_length_check_ids {
        check_index_oid_length(ctx, obj_id);
    }
}

fn is_legal_index_basetype(base: BaseType) -> bool {
    matches!(
        base,
        BaseType::Integer32
            | BaseType::Unsigned32
            | BaseType::Gauge32
            | BaseType::TimeTicks
            | BaseType::Counter32
            | BaseType::Counter64
            | BaseType::Bits
            | BaseType::OctetString
            | BaseType::Opaque
            | BaseType::IpAddress
            | BaseType::ObjectIdentifier
    )
}

fn check_index_oid_length(ctx: &mut ResolverContext, obj_id: ObjectId) {
    let obj = ctx.mib.raw().object(obj_id);
    let node_id = match obj.node() {
        Some(n) => n,
        None => return,
    };
    let row_oid = ctx.mib.tree().oid_of(node_id);
    let mut total_len = row_oid.len();

    for entry in obj.index() {
        let n = match index_element_sub_ids(ctx, entry) {
            Some(n) => n,
            None => return, // can't compute, skip
        };
        total_len += n;
    }

    if total_len > 128 {
        let excess = total_len - 128;
        let ir_mod = obj
            .module()
            .and_then(|m| ctx.resolved_to_module.get(&m).copied());
        ctx.emit_diagnostic(
            DiagCode::IndexExceedsTooLarge,
            ir_mod,
            obj.span(),
            format!(
                "{:?} index OID exceeds 128 sub-identifiers by {}",
                obj.name(),
                excess
            ),
        );
    }
}

fn index_element_sub_ids(
    ctx: &ResolverContext,
    entry: &crate::mib::types::IndexEntry,
) -> Option<usize> {
    use crate::types::IndexEncoding;
    let obj_id = entry.object?;
    let obj = ctx.mib.raw().object(obj_id);
    match entry.encoding {
        IndexEncoding::Integer => Some(1),
        IndexEncoding::IpAddress => Some(4),
        IndexEncoding::FixedString => {
            let sizes = obj.effective_sizes();
            if sizes.is_empty() {
                return None;
            }
            Some(sizes[0].max as usize)
        }
        IndexEncoding::LengthPrefixed => {
            let base = obj
                .typ
                .map(|tid| ctx.mib.raw().type_(tid).effective_base(ctx.mib.types_slice()))?;
            if base == BaseType::ObjectIdentifier {
                return Some(129);
            }
            let max = obj.effective_sizes().iter().map(|r| r.max).max()?;
            usize::try_from(max).ok().map(|n| n + 1)
        }
        IndexEncoding::Implied => {
            let base = obj
                .typ
                .map(|tid| ctx.mib.raw().type_(tid).effective_base(ctx.mib.types_slice()))?;
            if base == BaseType::ObjectIdentifier {
                return Some(128);
            }
            let max = obj.effective_sizes().iter().map(|r| r.max).max()?;
            usize::try_from(max).ok()
        }
        IndexEncoding::Unknown => None,
    }
}

// --- Enum subtyping ---

fn check_enum_subtyping(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let (name, syntax, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, &ot.syntax, ot.span),
                ir::Definition::TypeDef(td) => (&td.name, &td.syntax, td.span),
                _ => continue,
            };

            check_enum_subtyping_syntax(&mut diags, ctx, ir_id, name, syntax, span);
        }
    }

    emit_all(ctx, diags);
}

fn check_enum_subtyping_syntax(
    diags: &mut Vec<Diag>,
    ctx: &ResolverContext,
    ir_id: IrModuleId,
    name: &str,
    syntax: &ir::TypeSyntax,
    span: Span,
) {
    let (base_name, named_numbers) = match syntax {
        ir::TypeSyntax::IntegerEnum {
            base,
            named_numbers,
            ..
        } if !base.is_empty() && !named_numbers.is_empty() => (base.as_str(), named_numbers),
        _ => return,
    };

    let parent_type_id = match ctx.lookup_type_for_module(ir_id, base_name) {
        Some((id, _)) => id,
        None => return,
    };

    let parent_type = ctx.mib.raw().type_(parent_type_id);
    let parent_bits = parent_type.effective_bits(ctx.mib.types_slice());
    let parent_enums = parent_type.effective_enums(ctx.mib.types_slice());

    let (parent_values, diag_code, label) = if !parent_bits.is_empty() {
        (parent_bits, DiagCode::SubtypeBitsIllegal, "BITS value")
    } else if !parent_enums.is_empty() {
        (parent_enums, DiagCode::SubtypeEnumIllegal, "enum value")
    } else {
        return;
    };

    for nn in named_numbers {
        let found = parent_values
            .iter()
            .any(|pv| pv.label == nn.name && pv.value == nn.value);
        if !found {
            diags.push(Diag {
                code: diag_code,
                ir_id: Some(ir_id),
                span,
                message: format!(
                    "{:?}: {} {}({}) not in parent type {:?}",
                    name, label, nn.name, nn.value, base_name
                ),
            });
        }
    }
}

// --- Hyphen in label ---

fn check_smiv2_identifier_hyphens(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            if def.oid().is_some() && def.name().contains('-') {
                diags.push(Diag {
                    code: DiagCode::IdentifierHyphenSMIv2,
                    ir_id: Some(ir_id),
                    span: def.span(),
                    message: format!(
                        "identifier {:?} should not contain hyphens in SMIv2 MIB",
                        def.name()
                    ),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

fn check_hyphen_in_label(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for def in &m.definitions {
            let (name, syntax, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, &ot.syntax, ot.span),
                ir::Definition::TypeDef(td) => (&td.name, &td.syntax, td.span),
                _ => continue,
            };
            check_hyphen_in_syntax(&mut diags, ir_id, name, syntax, span);
        }
    }

    emit_all(ctx, diags);
}

fn check_hyphen_in_syntax(
    diags: &mut Vec<Diag>,
    ir_id: IrModuleId,
    name: &str,
    syntax: &ir::TypeSyntax,
    span: Span,
) {
    match syntax {
        ir::TypeSyntax::IntegerEnum { named_numbers, .. } => {
            for nn in named_numbers {
                if nn.name.contains('-') {
                    diags.push(Diag {
                        code: DiagCode::HyphenInLabel,
                        ir_id: Some(ir_id),
                        span,
                        message: format!(
                            "{:?}: named number {:?} contains a hyphen",
                            name, nn.name
                        ),
                    });
                }
            }
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            for nb in named_bits {
                if nb.name.contains('-') {
                    diags.push(Diag {
                        code: DiagCode::HyphenInLabel,
                        ir_id: Some(ir_id),
                        span,
                        message: format!("{:?}: BITS label {:?} contains a hyphen", name, nb.name),
                    });
                }
            }
        }
        ir::TypeSyntax::Constrained { base, .. } => {
            check_hyphen_in_syntax(diags, ir_id, name, base, span);
        }
        _ => {}
    }
}

// --- Format hints ---

fn check_format_hints(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let td = match def {
                ir::Definition::TypeDef(td) if td.is_textual_convention => td,
                _ => continue,
            };

            let type_id = match ctx
                .module_symbol_to_type
                .get(&ir_id)
                .and_then(|syms| syms.get(&td.name))
                .copied()
            {
                Some(id) => id,
                None => continue,
            };

            let t = ctx.mib.raw().type_(type_id);
            let base = {
                let effective = t.effective_base(ctx.mib.types_slice());
                if effective == BaseType::Unknown {
                    diagnostic_base_from_syntax(&td.syntax).unwrap_or(BaseType::Unknown)
                } else {
                    effective
                }
            };

            if !td.display_hint.is_empty() {
                let valid = match base {
                    BaseType::Integer32
                    | BaseType::Unsigned32
                    | BaseType::Gauge32
                    | BaseType::TimeTicks => validate_display_hint_integer(&td.display_hint),
                    BaseType::OctetString | BaseType::Opaque => {
                        validate_display_hint_octet_string(&td.display_hint)
                    }
                    _ => false,
                };
                if !valid {
                    diags.push(Diag {
                        code: DiagCode::InvalidFormat,
                        ir_id: Some(ir_id),
                        span: td.span,
                        message: format!(
                            "{:?}: invalid DISPLAY-HINT {:?} for base type {:?}",
                            td.name, td.display_hint, base
                        ),
                    });
                }
            } else if t.effective_display_hint(ctx.mib.types_slice()).is_empty()
                && matches!(
                    base,
                    BaseType::OctetString
                        | BaseType::Integer32
                        | BaseType::Unsigned32
                        | BaseType::Gauge32
                )
            {
                diags.push(Diag {
                    code: DiagCode::TypeWithoutFormat,
                    ir_id: Some(ir_id),
                    span: td.span,
                    message: format!("{:?}: textual convention without DISPLAY-HINT", td.name),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

fn validate_display_hint_integer(hint: &str) -> bool {
    if hint.is_empty() {
        return false;
    }
    let bytes = hint.as_bytes();
    match bytes[0] {
        b'x' | b'o' | b'b' => bytes.len() == 1,
        b'd' => {
            if bytes.len() == 1 {
                return true;
            }
            if bytes.len() < 3 || bytes[1] != b'-' {
                return false;
            }
            bytes[2..].iter().all(|b| b.is_ascii_digit())
        }
        _ => false,
    }
}

fn validate_display_hint_octet_string(hint: &str) -> bool {
    if hint.is_empty() {
        return false;
    }
    let bytes = hint.as_bytes();
    let mut p = 0;
    let mut last_spec_consumes = false;

    while p < bytes.len() {
        // Optional repeat indicator
        let repeat = if bytes[p] == b'*' {
            p += 1;
            true
        } else {
            false
        };

        // Required octet count
        let mut n = 0;
        let mut take = 0;
        while p < bytes.len() && bytes[p].is_ascii_digit() {
            take = take * 10 + (bytes[p] - b'0') as usize;
            p += 1;
            n += 1;
        }
        if n == 0 {
            return false;
        }

        // Required format character
        if p >= bytes.len() {
            return false;
        }
        match bytes[p] {
            b'x' | b'd' | b'o' | b'a' | b't' => p += 1,
            _ => return false,
        }

        // Optional separator character
        if p < bytes.len() && bytes[p] != b'*' && !bytes[p].is_ascii_digit() {
            p += 1;
            // Optional repeat terminator
            if repeat && p < bytes.len() && bytes[p] != b'*' && !bytes[p].is_ascii_digit() {
                p += 1;
            }
        }

        last_spec_consumes = take > 0 || repeat;
    }

    last_spec_consumes
}

// --- Capabilities status ---

fn check_capabilities_status(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let ac = match def {
                ir::Definition::AgentCapabilities(ac) => ac,
                _ => continue,
            };
            if ac.status != Status::Current && ac.status != Status::Obsolete {
                diags.push(Diag {
                    code: DiagCode::StatusInvalidCapabilities,
                    ir_id: Some(ir_id),
                    span: ac.span,
                    message: format!(
                        "{:?}: AGENT-CAPABILITIES STATUS must be current or obsolete, got {}",
                        ac.name, ac.status
                    ),
                });
            }
        }
    }

    emit_all(ctx, diags);
}

// --- Type status usage ---

fn check_type_status_usage(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for i in 0..ctx.mib.objects_slice().len() {
        let obj_id = ObjectId::new(i as u32);
        let obj = ctx.mib.raw().object(obj_id);
        let module_id = match obj.module() {
            Some(m) => m,
            None => continue,
        };
        if ctx.mib.raw().module(module_id).is_base() {
            continue;
        }
        let type_id = match obj.type_id() {
            Some(t) => t,
            None => continue,
        };
        let t = ctx.mib.raw().type_(type_id);
        let ir_mod = ctx.resolved_to_module.get(&module_id).copied();

        match t.status() {
            Status::Deprecated => {
                diags.push(Diag {
                    code: DiagCode::TypeStatusDeprecated,
                    ir_id: ir_mod,
                    span: obj.span(),
                    message: format!("type {:?} used by {:?} is deprecated", t.name(), obj.name()),
                });
            }
            Status::Obsolete => {
                diags.push(Diag {
                    code: DiagCode::TypeStatusObsolete,
                    ir_id: ir_mod,
                    span: obj.span(),
                    message: format!("type {:?} used by {:?} is obsolete", t.name(), obj.name()),
                });
            }
            _ => {}
        }
    }

    emit_all(ctx, diags);
}

// --- Compliance status ---

fn check_compliance_status(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            let comp = match def {
                ir::Definition::ModuleCompliance(c) => c,
                _ => continue,
            };
            if comp.status.is_smiv1() {
                continue;
            }

            for cm in &comp.modules {
                // Check mandatory groups.
                for group_name in &cm.mandatory_groups {
                    check_compliance_group_status_inner(
                        &mut diags,
                        ctx,
                        ir_id,
                        comp,
                        &cm.module_name,
                        group_name,
                    );
                }
                // Check optional groups.
                for cg in &cm.groups {
                    check_compliance_group_status_inner(
                        &mut diags,
                        ctx,
                        ir_id,
                        comp,
                        &cm.module_name,
                        &cg.group,
                    );
                }
                // Check refined objects.
                for co in &cm.objects {
                    check_compliance_object_status_inner(
                        &mut diags,
                        ctx,
                        ir_id,
                        comp,
                        &cm.module_name,
                        &co.object,
                    );
                }
            }
        }
    }

    emit_all(ctx, diags);
}

fn check_compliance_group_status_inner(
    diags: &mut Vec<Diag>,
    ctx: &ResolverContext,
    ir_id: IrModuleId,
    comp: &ir::ModuleCompliance,
    module_name: &str,
    group_name: &str,
) {
    let node_id = lookup_compliance_member(ctx, ir_id, module_name, group_name);
    let node_id = match node_id {
        Some(n) => n,
        None => return,
    };
    let group_id = match ctx.mib.tree().get(node_id).group {
        Some(g) => g,
        None => return,
    };
    let gs = ctx.mib.raw().group(group_id).status();
    if gs.is_smiv1() {
        return;
    }
    if status_ord(gs) > status_ord(comp.status) {
        diags.push(Diag {
            code: DiagCode::ComplianceGroupStatus,
            ir_id: Some(ir_id),
            span: comp.span,
            message: format!(
                "{} compliance {:?} references {} group {:?}",
                comp.status, comp.name, gs, group_name
            ),
        });
    }
}

fn check_compliance_object_status_inner(
    diags: &mut Vec<Diag>,
    ctx: &ResolverContext,
    ir_id: IrModuleId,
    comp: &ir::ModuleCompliance,
    module_name: &str,
    object_name: &str,
) {
    let node_id = lookup_compliance_member(ctx, ir_id, module_name, object_name);
    let node_id = match node_id {
        Some(n) => n,
        None => return,
    };
    let node = ctx.mib.tree().get(node_id);
    let ms = match node.object {
        Some(obj_id) => ctx.mib.raw().object(obj_id).status(),
        None => match node.notification {
            Some(nid) => ctx.mib.raw().notification(nid).status(),
            None => return,
        },
    };
    if ms.is_smiv1() {
        return;
    }
    if status_ord(ms) > status_ord(comp.status) {
        diags.push(Diag {
            code: DiagCode::ComplianceObjectStatus,
            ir_id: Some(ir_id),
            span: comp.span,
            message: format!(
                "{} compliance {:?} references {} object {:?}",
                comp.status, comp.name, ms, object_name
            ),
        });
    }
}

fn lookup_compliance_member(
    ctx: &ResolverContext,
    comp_ir: IrModuleId,
    module_name: &str,
    name: &str,
) -> Option<NodeId> {
    if !module_name.is_empty()
        && let Some(n) = ctx.lookup_node_in_module(module_name, name)
    {
        return Some(n);
    }
    if let Some((n, _)) = ctx.lookup_node_for_module(comp_ir, name) {
        return Some(n);
    }
    if ctx.strictness.allow_global_fallbacks() {
        return ctx.lookup_node_global(name);
    }
    None
}

/// Map status to an ordinal for comparison.
fn status_ord(s: Status) -> u8 {
    match s {
        Status::Current => 0,
        Status::Deprecated => 1,
        Status::Obsolete => 2,
        _ => 0,
    }
}

// --- Group unreferenced ---

fn check_group_unreferenced(ctx: &mut ResolverContext) {
    let mut referenced_groups: HashSet<String> = HashSet::new();

    for (_, m) in ctx.all_modules() {
        for def in &m.definitions {
            match def {
                ir::Definition::ModuleCompliance(c) => {
                    for cm in &c.modules {
                        for name in &cm.mandatory_groups {
                            referenced_groups.insert(name.clone());
                        }
                        for g in &cm.groups {
                            referenced_groups.insert(g.group.clone());
                        }
                    }
                }
                ir::Definition::AgentCapabilities(ac) => {
                    for sup in &ac.supports {
                        for name in &sup.includes {
                            referenced_groups.insert(name.clone());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let mut diags = Vec::new();

    for (ir_id, m) in ctx.user_modules() {
        for def in &m.definitions {
            match def {
                ir::Definition::ObjectGroup(g) => {
                    if !referenced_groups.contains(&g.name) {
                        diags.push(Diag {
                            code: DiagCode::GroupUnreferenced,
                            ir_id: Some(ir_id),
                            span: g.span,
                            message: format!(
                                "{:?}: OBJECT-GROUP not referenced in any compliance module",
                                g.name
                            ),
                        });
                    }
                }
                ir::Definition::NotificationGroup(g) => {
                    if !referenced_groups.contains(&g.name) {
                        diags.push(Diag {
                            code: DiagCode::GroupUnreferenced,
                            ir_id: Some(ir_id),
                            span: g.span,
                            message: format!(
                                "{:?}: NOTIFICATION-GROUP not referenced in any compliance module",
                                g.name
                            ),
                        });
                    }
                }
                _ => {}
            }
        }
    }

    emit_all(ctx, diags);
}

// --- IpAddress deprecation ---

fn check_ip_address_deprecation(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for i in 0..ctx.mib.objects_slice().len() {
        let obj_id = ObjectId::new(i as u32);
        let obj = ctx.mib.raw().object(obj_id);
        let module_id = match obj.module() {
            Some(m) => m,
            None => continue,
        };
        let module = ctx.mib.raw().module(module_id);
        if module.language() != Language::SMIv2 || module.is_base() {
            continue;
        }
        let type_id = match obj.type_id() {
            Some(t) => t,
            None => continue,
        };
        let t = ctx.mib.raw().type_(type_id);
        if t.effective_base(ctx.mib.types_slice()) == BaseType::IpAddress {
            let ir_mod = ctx.resolved_to_module.get(&module_id).copied();
            diags.push(Diag {
                code: DiagCode::IpAddressInSyntax,
                ir_id: ir_mod,
                span: obj.span(),
                message: format!(
                    "{:?}: IpAddress is deprecated, use InetAddress (RFC 4001)",
                    obj.name()
                ),
            });
        }
    }

    emit_all(ctx, diags);
}

/// Format an ir::Range as "min..max" or just "value" if min equals max.
fn format_ir_range(r: &ir::Range) -> String {
    let min_s = format_range_value(&r.min);
    match &r.max {
        Some(max) => {
            let max_s = format_range_value(max);
            if min_s == max_s {
                min_s
            } else {
                format!("{min_s}..{max_s}")
            }
        }
        None => min_s,
    }
}

fn format_range_value(v: &ir::RangeValue) -> String {
    match v {
        ir::RangeValue::Signed(n) => n.to_string(),
        ir::RangeValue::Unsigned(n) => n.to_string(),
        ir::RangeValue::Min => "MIN".to_string(),
        ir::RangeValue::Max => "MAX".to_string(),
    }
}

/// Compare two RangeValue endpoints. Returns true if a > b.
fn range_value_gt(a: &ir::RangeValue, b: &ir::RangeValue) -> bool {
    match (a, b) {
        (ir::RangeValue::Max, ir::RangeValue::Max) => false,
        (ir::RangeValue::Max, _) => true,
        (_, ir::RangeValue::Max) => false,
        (ir::RangeValue::Min, _) => false,
        (_, ir::RangeValue::Min) => true,
        (ir::RangeValue::Signed(x), ir::RangeValue::Signed(y)) => x > y,
        (ir::RangeValue::Unsigned(x), ir::RangeValue::Unsigned(y)) => x > y,
        (ir::RangeValue::Signed(x), ir::RangeValue::Unsigned(y)) => {
            if *x < 0 {
                false
            } else {
                (*x as u64) > *y
            }
        }
        (ir::RangeValue::Unsigned(x), ir::RangeValue::Signed(y)) => {
            if *y < 0 {
                true
            } else {
                *x > (*y as u64)
            }
        }
    }
}
