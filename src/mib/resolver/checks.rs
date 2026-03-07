use std::collections::{HashMap, HashSet};

use crate::ir;
use crate::lower::base_modules;
use crate::types::{Access, AccessKeyword, BaseType, DiagCode, Kind, Language, Span, Status};

use super::super::types::{ModuleId, NodeId, ObjectId, TypeId};
use super::context::{IrModuleId, ResolverContext};

type Diag = (DiagCode, Option<IrModuleId>, Span, String);

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
}

fn emit_all(ctx: &mut ResolverContext, diags: Vec<Diag>) {
    for (code, ir_id, span, msg) in diags {
        ctx.emit_diagnostic(code, ir_id, span, msg);
    }
}

/// Validate ACCESS and STATUS values per SMI version and node kind.
fn check_access_and_status(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }
        let lang = m.language;

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
            if lang == Language::SMIv1 {
                if matches!(
                    ot.access_keyword,
                    AccessKeyword::MaxAccess | AccessKeyword::MinAccess
                ) {
                    diags.push((
                        DiagCode::MaxAccessInSMIv1,
                        Some(ir_id),
                        ot.access_span,
                        format!("{}: MAX-ACCESS/MIN-ACCESS in SMIv1 module", ot.name),
                    ));
                }
                if ot.access == Access::WriteOnly {
                    diags.push((
                        DiagCode::AccessWriteOnlySMIv1,
                        Some(ir_id),
                        ot.access_span,
                        format!("{}: write-only access is discouraged", ot.name),
                    ));
                }
            } else if lang == Language::SMIv2 {
                if ot.access_keyword == AccessKeyword::Access {
                    diags.push((
                        DiagCode::AccessInSMIv2,
                        Some(ir_id),
                        ot.access_span,
                        format!("{}: use MAX-ACCESS instead of ACCESS in SMIv2", ot.name),
                    ));
                }
                if ot.access == Access::WriteOnly {
                    diags.push((
                        DiagCode::AccessWriteOnlySMIv2,
                        Some(ir_id),
                        ot.access_span,
                        format!("{}: write-only access is not valid in SMIv2", ot.name),
                    ));
                }
            }

            // Table/row access checks
            if kind == Kind::Table && ot.access != Access::NotAccessible {
                diags.push((
                    DiagCode::AccessTableIllegal,
                    Some(ir_id),
                    ot.access_span,
                    format!("{}: table must be not-accessible", ot.name),
                ));
            }
            if kind == Kind::Row && ot.access != Access::NotAccessible {
                diags.push((
                    DiagCode::AccessRowIllegal,
                    Some(ir_id),
                    ot.access_span,
                    format!("{}: row must be not-accessible", ot.name),
                ));
            }

            // Counter access check
            if let Some(type_id) = ctx
                .mib
                .tree()
                .get(node_id)
                .object
                .and_then(|oid| ctx.mib.object(oid).typ)
            {
                let t = ctx.mib.type_(type_id);
                let base = t.effective_base(ctx.mib.types_slice());
                if (base == BaseType::Counter32 || base == BaseType::Counter64)
                    && !matches!(
                        ot.access,
                        Access::ReadOnly | Access::AccessibleForNotify
                    )
                {
                    diags.push((
                        DiagCode::AccessCounterIllegal,
                        Some(ir_id),
                        ot.access_span,
                        format!("{}: counter must be read-only or accessible-for-notify", ot.name),
                    ));
                }
            }

            // Status checks
            if lang == Language::SMIv2 && ot.status.is_smiv1() {
                diags.push((
                    DiagCode::StatusInvalidSMIv2,
                    Some(ir_id),
                    ot.status_span,
                    format!("{}: invalid SMIv2 status {}", ot.name, ot.status),
                ));
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate parent node kinds per SMI structural rules.
fn check_node_parent_kinds(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

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
                        diags.push((
                            DiagCode::ParentTable,
                            Some(ir_id),
                            ot.span,
                            format!("{}: table's parent must be a simple node", ot.name),
                        ));
                    }
                }
                Kind::Row => {
                    if parent_kind != Kind::Table {
                        diags.push((
                            DiagCode::ParentRow,
                            Some(ir_id),
                            ot.span,
                            format!("{}: row's parent must be a table", ot.name),
                        ));
                    } else if node.arc != 1 {
                        diags.push((
                            DiagCode::RowSubidentifierOne,
                            Some(ir_id),
                            ot.span,
                            format!("{}: row must have sub-identifier 1", ot.name),
                        ));
                    }
                }
                Kind::Column => {
                    if parent_kind != Kind::Row {
                        diags.push((
                            DiagCode::ParentColumn,
                            Some(ir_id),
                            ot.span,
                            format!("{}: column's parent must be a row", ot.name),
                        ));
                    }
                }
                Kind::Scalar => {
                    if !is_simple_parent_kind(parent_kind) {
                        diags.push((
                            DiagCode::ParentScalar,
                            Some(ir_id),
                            ot.span,
                            format!("{}: scalar's parent must be a simple node", ot.name),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    emit_all(ctx, diags);
}

fn is_simple_parent_kind(k: Kind) -> bool {
    matches!(k, Kind::Node | Kind::Internal | Kind::Unknown)
}

/// Check table/row naming conventions.
fn check_table_row_naming(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

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
                diags.push((
                    DiagCode::TableNameTable,
                    Some(ir_id),
                    ot.span,
                    format!("{}: table name should end with 'Table'", ot.name),
                ));
            }

            if kind == Kind::Row && !ot.name.ends_with("Entry") {
                diags.push((
                    DiagCode::RowNameEntry,
                    Some(ir_id),
                    ot.span,
                    format!("{}: row name should end with 'Entry'", ot.name),
                ));
            }

            // Check row name prefix matches table name prefix.
            if kind == Kind::Row {
                let node = ctx.mib.tree().get(node_id);
                if let Some(parent_id) = node.parent {
                    let parent = ctx.mib.tree().get(parent_id);
                    if parent.kind == Kind::Table {
                        let table_prefix = parent.name.strip_suffix("Table").unwrap_or(&parent.name);
                        let row_prefix = ot.name.strip_suffix("Entry").unwrap_or(&ot.name);
                        if !table_prefix.is_empty()
                            && !row_prefix.is_empty()
                            && table_prefix != row_prefix
                        {
                            diags.push((
                                DiagCode::RowNameTableName,
                                Some(ir_id),
                                ot.span,
                                format!(
                                    "{}: row prefix {:?} does not match table prefix {:?}",
                                    ot.name, row_prefix, table_prefix
                                ),
                            ));
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

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if m.language != Language::SMIv2 || base_modules::is_base_module(&m.name) {
            continue;
        }

        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };
            if !ot.has_description {
                diags.push((
                    DiagCode::DescriptionMissing,
                    Some(ir_id),
                    ot.span,
                    format!("{}: OBJECT-TYPE should have a DESCRIPTION clause", ot.name),
                ));
            }
        }
    }

    emit_all(ctx, diags);
}

/// Flag bare INTEGER usage in SMIv2 (should use Integer32 for non-enum use).
fn check_integer_misuse(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if m.language != Language::SMIv2 || base_modules::is_base_module(&m.name) {
            continue;
        }

        for def in &m.definitions {
            let (name, syntax, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, &ot.syntax, ot.span),
                ir::Definition::TypeDef(td) => (&td.name, &td.syntax, td.span),
                _ => continue,
            };
            if is_integer_keyword_syntax(syntax) {
                diags.push((
                    DiagCode::IntegerInSMIv2,
                    Some(ir_id),
                    span,
                    format!("{}: use Integer32 instead of INTEGER in SMIv2", name),
                ));
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

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if m.language != Language::SMIv2 || base_modules::is_base_module(&m.name) {
            continue;
        }

        for def in &m.definitions {
            if let ir::Definition::Notification(n) = def {
                if n.trap_info.is_some() {
                    diags.push((
                        DiagCode::TrapInSMIv2,
                        Some(ir_id),
                        n.span,
                        format!(
                            "{}: use NOTIFICATION-TYPE instead of TRAP-TYPE in SMIv2",
                            n.name
                        ),
                    ));
                }
            }
        }
    }

    emit_all(ctx, diags);
}

/// Warn about unreferenced type definitions.
fn check_type_unreferenced(ctx: &mut ResolverContext) {
    let mut referenced: std::collections::HashSet<String> = std::collections::HashSet::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        if base_modules::is_base_module(&m.name) {
            continue;
        }
        for def in &m.definitions {
            if let ir::Definition::ObjectType(ot) = def {
                collect_type_refs(&ot.syntax, &mut referenced);
            }
        }
    }

    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def {
                if td.is_textual_convention && !referenced.contains(&td.name) {
                    diags.push((
                        DiagCode::TypeUnreferenced,
                        Some(ir_id),
                        td.span,
                        format!("{}: textual convention is never referenced", td.name),
                    ));
                }
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

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

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
                    diags.push((
                        DiagCode::NamedNumbersAscending,
                        Some(ir_id),
                        span,
                        format!("{}: named numbers should be in ascending order", name),
                    ));
                    break;
                }
            }
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            for i in 1..named_bits.len() {
                if named_bits[i].position < named_bits[i - 1].position {
                    diags.push((
                        DiagCode::NamedNumbersAscending,
                        Some(ir_id),
                        span,
                        format!("{}: bit positions should be in ascending order", name),
                    ));
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

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

        for def in &m.definitions {
            let (name, syntax, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, &ot.syntax, ot.span),
                ir::Definition::TypeDef(td) => (&td.name, &td.syntax, td.span),
                _ => continue,
            };

            collect_range_diags(&mut diags, ir_id, name, syntax, span);
        }
    }

    emit_all(ctx, diags);
}

fn collect_range_diags(
    diags: &mut Vec<Diag>,
    ir_id: IrModuleId,
    name: &str,
    syntax: &ir::TypeSyntax,
    span: Span,
) {
    if let ir::TypeSyntax::Constrained { constraint, .. } = syntax {
        let ranges = match constraint {
            ir::Constraint::Range { ranges, .. } | ir::Constraint::Size { ranges, .. } => ranges,
        };
        for r in ranges {
            if let Some(ref max) = r.max {
                if range_value_gt(&r.min, max) {
                    diags.push((
                        DiagCode::RangeExchanged,
                        Some(ir_id),
                        span,
                        format!("{}: range min ({:?}) > max ({:?})", name, r.min, max),
                    ));
                }
            }
        }
        for i in 1..ranges.len() {
            let prev_end = ranges[i - 1].max.as_ref().unwrap_or(&ranges[i - 1].min);
            if !range_value_gt(&ranges[i].min, prev_end) {
                diags.push((
                    DiagCode::RangeOverlap,
                    Some(ir_id),
                    span,
                    format!("{}: ranges overlap or are not ascending", name),
                ));
                break;
            }
        }
    }
}

/// Flag plain type assignments in SMIv2 (should use TEXTUAL-CONVENTION).
fn check_type_assignment_smiv2(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if m.language != Language::SMIv2 || base_modules::is_base_module(&m.name) {
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
                diags.push((
                    DiagCode::TypeAssignmentSMIv2,
                    Some(ir_id),
                    td.span,
                    format!(
                        "{}: type assignment in SMIv2 should be a TEXTUAL-CONVENTION",
                        td.name
                    ),
                ));
            }
        }
    }

    emit_all(ctx, diags);
}

/// Flag TEXTUAL-CONVENTIONs derived from other TCs (RFC 2579 s3.5).
fn check_tc_nested(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

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

            let t = ctx.mib.type_(type_id);
            if let Some(parent_id) = t.parent() {
                let parent = ctx.mib.type_(parent_id);
                if parent.is_textual_convention() {
                    diags.push((
                        DiagCode::TCNested,
                        Some(ir_id),
                        td.span,
                        format!(
                            "{}: textual convention derived from textual convention {}",
                            td.name,
                            parent.name()
                        ),
                    ));
                }
            }
        }
    }

    emit_all(ctx, diags);
}

/// Flag OBJECT-TYPE using Opaque in SMIv2 (RFC 2578 s7.1.3).
fn check_opaque_smiv2(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if m.language != Language::SMIv2 || base_modules::is_base_module(&m.name) {
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
            let type_id = match ctx.mib.object(obj_id).typ {
                Some(id) => id,
                None => continue,
            };

            let t = ctx.mib.type_(type_id);
            if t.effective_base(ctx.mib.types_slice()) == BaseType::Opaque {
                diags.push((
                    DiagCode::OpaqueSMIv2,
                    Some(ir_id),
                    ot.span,
                    format!("{}: Opaque type should not be used in SMIv2", ot.name),
                ));
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate notification OID structure for SNMPv1 reverse mapping (RFC 2578 s8.5).
fn check_notification_reversibility(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if m.language != Language::SMIv2 || base_modules::is_base_module(&m.name) {
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
                diags.push((
                    DiagCode::NotifIdTooLarge,
                    Some(ir_id),
                    n.span,
                    format!(
                        "last sub-identifier of notification {} is too large",
                        n.name
                    ),
                ));
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
                diags.push((
                    DiagCode::NotifNotReversible,
                    Some(ir_id),
                    n.span,
                    format!("notification {} is not reverse mappable", n.name),
                ));
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
        for (_, &child_id) in node.children() {
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
                child_node.module.and_then(|mod_id| {
                    ctx.resolved_to_module.get(&mod_id).copied()
                })
            })
            .next();

        let oid = ctx.mib.tree().oid_of(nid);
        diags.push((
            DiagCode::NodeImplicit,
            ir_id,
            Span::ZERO,
            format!("implicit node at OID {}", oid),
        ));
    }

    emit_all(ctx, diags);
}

/// Flag identifiers within a module differing only in case.
fn check_identifier_case_match(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

        // Group definitions by lowercased name, excluding SEQUENCE types.
        let mut by_lower: HashMap<String, Vec<(&str, Span)>> = HashMap::new();
        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def {
                if matches!(td.syntax, ir::TypeSyntax::Sequence { .. }) {
                    continue;
                }
            }
            let name = def.name();
            let span = def.span();
            by_lower
                .entry(name.to_lowercase())
                .or_default()
                .push((name, span));
        }

        for (_key, defs) in &by_lower {
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
                diags.push((
                    DiagCode::IdentifierCaseMatch,
                    Some(ir_id),
                    span,
                    format!("{}: differs from {} only in case", name, first_name),
                ));
            }
        }
    }

    emit_all(ctx, diags);
}

/// Validate status per SMI version across all definition types.
fn check_status_per_version(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

        for def in &m.definitions {
            let (name, status, span) = match def {
                ir::Definition::ObjectType(ot) => (&ot.name, ot.status, ot.status_span),
                ir::Definition::ObjectIdentity(oi) => (&oi.name, oi.status, oi.span),
                ir::Definition::Notification(n) => (&n.name, n.status, n.span),
                ir::Definition::TypeDef(td) if td.is_textual_convention => {
                    (&td.name, td.status, td.status_span)
                }
                ir::Definition::ObjectGroup(g) => (&g.name, g.status, g.span),
                ir::Definition::NotificationGroup(g) => (&g.name, g.status, g.span),
                ir::Definition::ModuleCompliance(c) => (&c.name, c.status, c.span),
                _ => continue,
            };

            match m.language {
                Language::SMIv1 => {
                    if status == Status::Current {
                        // "current" is technically SMIv2 but widely used in v1.
                        // Only flag if strict. The DiagCode severity handles this.
                        diags.push((
                            DiagCode::StatusInvalidSMIv1,
                            Some(ir_id),
                            span,
                            format!("{}: 'current' is SMIv2 style status", name),
                        ));
                    }
                }
                Language::SMIv2 => {
                    if status.is_smiv1() {
                        diags.push((
                            DiagCode::StatusInvalidSMIv2,
                            Some(ir_id),
                            span,
                            format!("{}: invalid SMIv2 status {}", name, status),
                        ));
                    }
                }
                _ => {}
            }

            // SMIv1 access per version (accessible-for-notify/read-create invalid).
            if let ir::Definition::ObjectType(ot) = def {
                if m.language == Language::SMIv1 {
                    if matches!(
                        ot.access,
                        Access::AccessibleForNotify | Access::ReadCreate
                    ) {
                        diags.push((
                            DiagCode::AccessInvalidSMIv1,
                            Some(ir_id),
                            ot.access_span,
                            format!(
                                "{}: invalid access {} in SMIv1",
                                ot.name, ot.access
                            ),
                        ));
                    }
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
                        diags.push((
                            DiagCode::ScalarNotCreatable,
                            Some(ir_id),
                            ot.access_span,
                            format!("{}: scalar must not be read-create", ot.name),
                        ));
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

    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);
        if base_modules::is_base_module(&m.name) {
            continue;
        }

        // Find SEQUENCE type definitions in this module.
        let mut seq_types: HashMap<String, &[ir::SequenceField]> = HashMap::new();
        for def in &m.definitions {
            if let ir::Definition::TypeDef(td) = def {
                if let ir::TypeSyntax::Sequence { fields, .. } = &td.syntax {
                    seq_types.insert(td.name.clone(), fields);
                }
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
                    diags.push((
                        DiagCode::SequenceNoColumn,
                        Some(ir_id),
                        field.span,
                        format!(
                            "{}: SEQUENCE field {} has no matching column",
                            ot.name, field.name
                        ),
                    ));
                }
            }

            // Check each column has a matching SEQUENCE field.
            let field_names: HashSet<&str> =
                fields.iter().map(|f| f.name.as_str()).collect();
            for &child_id in node.children().values() {
                let child = ctx.mib.tree().get(child_id);
                if !child.name.is_empty() && !field_names.contains(child.name.as_str()) {
                    diags.push((
                        DiagCode::SequenceMissingColumn,
                        Some(ir_id),
                        ot.span,
                        format!(
                            "{}: column {} has no matching SEQUENCE field",
                            ot.name, child.name
                        ),
                    ));
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
                diags.push((
                    DiagCode::SequenceOrder,
                    Some(ir_id),
                    ot.span,
                    format!(
                        "{}: SEQUENCE field order does not match column order",
                        ot.name
                    ),
                ));
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
                let col_type_id = match ctx.mib.object(col_obj_id).typ {
                    Some(id) => id,
                    None => continue,
                };
                let field_type_name = sequence_field_type_name(&field.syntax);
                if field_type_name.is_empty() {
                    continue;
                }
                let col_type = ctx.mib.type_(col_type_id);
                let col_type_name = col_type.name();
                let col_base = col_type.effective_base(ctx.mib.types_slice());
                if !sequence_types_compatible(&field_type_name, col_type_name, col_base) {
                    diags.push((
                        DiagCode::SequenceTypeMismatch,
                        Some(ir_id),
                        field.span,
                        format!(
                            "{}: SEQUENCE field {} type {:?} does not match column type {:?}",
                            seq_name, field.name, field_type_name, col_type_name
                        ),
                    ));
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
            let grp = ctx.mib.group(gid);
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
        let obj = ctx.mib.object(obj_id);
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
            diags.push((
                DiagCode::GroupMembership,
                ir_mod,
                obj.span(),
                format!("{:?} is not in any OBJECT-GROUP", obj.name()),
            ));
        }
    }

    let notif_ids: Vec<crate::mib::NotificationId> = (0..ctx.mib.notifications_slice().len())
        .map(|i| crate::mib::NotificationId::new(i as u32))
        .collect();
    for notif_id in notif_ids {
        let notif = ctx.mib.notification(notif_id);
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
            diags.push((
                DiagCode::GroupMembership,
                ir_mod,
                notif.span(),
                format!("{:?} is not in any NOTIFICATION-GROUP", notif.name()),
            ));
        }
    }
    emit_all(ctx, diags);
}

fn check_group_member_locality(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let m = &ctx.modules[idx];
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
                    diags.push((
                        DiagCode::ComplianceMemberNotLocal,
                        Some(ir_id),
                        span,
                        format!("group member {:?} is not defined in module {:?}", member, m.name),
                    ));
                }
            }
        }
    }
    emit_all(ctx, diags);
}

fn check_compliance_structure(ctx: &mut ResolverContext) {
    let mut diags = Vec::new();
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let m = &ctx.modules[idx];
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
                        diags.push((
                            DiagCode::ComplianceGroupInvalid,
                            Some(ir_id),
                            comp.span,
                            format!(
                                "group {:?} is both mandatory and optional in {:?}",
                                g.group, comp.name
                            ),
                        ));
                    }
                    if !optional_seen.insert(g.group.as_str()) {
                        diags.push((
                            DiagCode::OptionalGroupExists,
                            Some(ir_id),
                            comp.span,
                            format!("duplicate optional group {:?} in {:?}", g.group, comp.name),
                        ));
                    }
                }

                let mut refinement_seen = HashSet::new();
                for o in &cm.objects {
                    if !refinement_seen.insert(o.object.as_str()) {
                        diags.push((
                            DiagCode::RefinementExists,
                            Some(ir_id),
                            comp.span,
                            format!("duplicate refinement for {:?} in {:?}", o.object, comp.name),
                        ));
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
                        diags.push((
                            DiagCode::RefinementNotListed,
                            Some(ir_id),
                            comp.span,
                            format!(
                                "refined object {:?} not in any mandatory or optional group of {:?}",
                                o.object, comp.name
                            ),
                        ));
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
        ctx.lookup_node_for_module(from_ir, group_name).map(|(n, _)| n)
    } else {
        ctx.lookup_node_in_module(&cm.module_name, group_name)
    };
    let Some(node_id) = node else {
        return;
    };
    let Some(group_id) = ctx.mib.tree().get(node_id).group else {
        return;
    };
    for &member_node in ctx.mib.group(group_id).members() {
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
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let m = &ctx.modules[idx];
        if base_modules::is_base_module(&m.name) {
            continue;
        }
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
                diags.push((
                    DiagCode::ModuleIdentityReg,
                    Some(ir_id),
                    mi.span,
                    format!("{:?}: MODULE-IDENTITY OID too short for valid registration", mi.name),
                ));
                continue;
            }
            if !oid.starts_with(MGMT) {
                continue;
            }
            if oid.starts_with(MIB2) || oid.starts_with(TRANSMISSION) || oid.starts_with(SNMP_MODULES)
            {
                continue;
            }
            diags.push((
                DiagCode::ModuleIdentityReg,
                Some(ir_id),
                mi.span,
                format!(
                    "{:?}: MODULE-IDENTITY registered under uncontrolled mgmt OID {}",
                    mi.name, oid
                ),
            ));
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
        let obj = ctx.mib.object(obj_id);
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
        let lang = ctx.mib.module(module_id).language();
        let access = obj.access();
        if lang == Language::SMIv2 && access != Access::ReadCreate {
            diags.push((
                DiagCode::RowStatusAccess,
                Some(ir_mod),
                obj.span(),
                format!(
                    "{:?}: RowStatus should have MAX-ACCESS read-create, has {}",
                    obj.name(),
                    access
                ),
            ));
        } else if lang == Language::SMIv1 && access != Access::ReadWrite {
            diags.push((
                DiagCode::RowStatusAccess,
                Some(ir_mod),
                obj.span(),
                format!(
                    "{:?}: RowStatus should have ACCESS read-write, has {}",
                    obj.name(),
                    access
                ),
            ));
        }

        let Some(dv) = obj.default_value() else {
            continue;
        };
        let Some(v) = defval_as_i64(dv, &row_status_actions) else {
            continue;
        };
        if let Some(name) = row_status_actions.get(&v) {
            diags.push((
                DiagCode::RowStatusDefault,
                Some(ir_mod),
                obj.span(),
                format!(
                    "{:?}: RowStatus DEFVAL {}({}) is an action value, must be active(1), notInService(2), or notReady(3)",
                    obj.name(),
                    name,
                    v
                ),
            ));
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
        let obj = ctx.mib.object(obj_id);
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
            diags.push((
                DiagCode::StorageTypeDefault,
                Some(ir_mod),
                obj.span(),
                format!(
                    "{:?}: StorageType DEFVAL {}({}) is not a valid default, must be other(1), volatile(2), or nonVolatile(3)",
                    obj.name(),
                    name,
                    v
                ),
            ));
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
    check_address_pairing(ctx, t_address, t_domain, DiagCode::TAddressTDomain, "TAddress", "TDomain");
}

fn check_inet_address_pairing(ctx: &mut ResolverContext) {
    let Some(addr) = lookup_type_in_named_module(ctx, "INET-ADDRESS-MIB", "InetAddress") else {
        return;
    };
    let Some(addr_type) = lookup_type_in_named_module(ctx, "INET-ADDRESS-MIB", "InetAddressType") else {
        return;
    };
    check_address_pairing(
        ctx,
        addr,
        addr_type,
        DiagCode::InetAddressPairing,
        "InetAddress",
        "InetAddressType",
    );
}

fn check_transport_address_pairing(ctx: &mut ResolverContext) {
    let Some(addr) = lookup_type_in_named_module(ctx, "TRANSPORT-ADDRESS-MIB", "TransportAddress")
    else {
        return;
    };
    let Some(addr_type) =
        lookup_type_in_named_module(ctx, "TRANSPORT-ADDRESS-MIB", "TransportAddressType")
    else {
        return;
    };
    check_address_pairing(
        ctx,
        addr,
        addr_type,
        DiagCode::TransportAddressPairing,
        "TransportAddress",
        "TransportAddressType",
    );
}

fn check_address_pairing(
    ctx: &mut ResolverContext,
    address_type_id: TypeId,
    address_type_type_id: TypeId,
    diag: DiagCode,
    address_name: &str,
    address_type_name: &str,
) {
    let object_ids: Vec<ObjectId> = (0..ctx.mib.objects_slice().len())
        .map(|i| ObjectId::new(i as u32))
        .collect();

    for oid in object_ids {
        let obj = ctx.mib.object(oid);
        let Some(type_id) = obj.type_id() else {
            continue;
        };
        let Some(node_id) = obj.node() else {
            continue;
        };
        if ctx.mib.tree().get(node_id).kind != Kind::Column {
            continue;
        }
        if !is_derived_from_type(ctx, type_id, address_type_id) {
            continue;
        }
        let Some(row_id) = row_object_for_column(ctx, node_id) else {
            continue;
        };
        let mut found = false;
        for col in row_column_objects(ctx, row_id) {
            let Some(col_type) = ctx.mib.object(col).type_id() else {
                continue;
            };
            if is_derived_from_type(ctx, col_type, address_type_type_id) {
                found = true;
                break;
            }
        }
        if !found {
            let ir_mod = obj
                .module()
                .and_then(|m| ctx.resolved_to_module.get(&m).copied());
            ctx.emit_diagnostic(
                diag,
                ir_mod,
                obj.span(),
                format!(
                    "{:?}: {} column has no sibling with {} type",
                    obj.name(),
                    address_name,
                    address_type_name
                ),
            );
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
    let Some(row_node) = ctx.mib.object(row_obj).node() else {
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
        current = ctx.mib.type_(tid).parent();
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
            if *x < 0 { false } else { (*x as u64) > *y }
        }
        (ir::RangeValue::Unsigned(x), ir::RangeValue::Signed(y)) => {
            if *y < 0 { true } else { *x > (*y as u64) }
        }
    }
}
