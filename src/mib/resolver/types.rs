use std::collections::HashMap;

use tracing::{Level, enabled, trace};

use crate::graph;
use crate::ir;
use crate::types::{BaseType, DiagCode, Language, Span};

use super::super::typedef::TypeData;
use super::super::types::*;
use super::context::{IrModuleId, ResolverContext};

/// Phase 3: Build the type system.
pub(super) fn resolve_types(ctx: &mut ResolverContext) {
    seed_primitive_types(ctx);
    create_user_types(ctx);
    resolve_type_bases(ctx);
}

/// Create the four ASN.1 primitive types in SNMPv2-SMI.
fn seed_primitive_types(ctx: &mut ResolverContext) {
    let smi_id = match ctx.snmpv2_smi {
        Some(id) => id,
        None => return,
    };
    let resolved_id = match ctx.module_to_resolved.get(&smi_id) {
        Some(&id) => id,
        None => return,
    };

    let primitives = [
        ("INTEGER", BaseType::Integer32),
        ("OCTET STRING", BaseType::OctetString),
        ("OBJECT IDENTIFIER", BaseType::ObjectIdentifier),
        ("BITS", BaseType::Bits),
    ];

    for (name, base) in primitives {
        let mut td = TypeData::new(name.to_string());
        td.base = base;
        td.module = Some(resolved_id);
        let type_id = ctx.mib.add_type(td);
        ctx.module_symbol_to_type
            .entry(smi_id)
            .or_default()
            .insert(name.to_string(), type_id);
        ctx.mib.module_mut(resolved_id).add_type(name, type_id);
    }
}

/// Create a resolved Type for each TypeDef definition across all modules.
fn create_user_types(ctx: &mut ResolverContext) {
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let resolved_id = match ctx.module_to_resolved.get(&ir_id) {
            Some(&id) => id,
            None => continue,
        };

        let m = &ctx.modules[idx];
        for def in &m.definitions {
            let typedef = match def {
                ir::Definition::TypeDef(td) => td,
                _ => continue,
            };

            // Skip SEQUENCE type assignments (they are structural, not type definitions).
            if matches!(typedef.syntax, ir::TypeSyntax::Sequence { .. }) {
                continue;
            }

            let base = if let Some(bt) = typedef.base_type {
                bt
            } else {
                syntax_to_base_type(&typedef.syntax)
            };

            let mut td = TypeData::new(typedef.name.clone());
            td.span = typedef.span;
            td.syntax_span = typedef.syntax_span;
            td.module = Some(resolved_id);
            td.base = base;
            td.status = typedef.status;
            td.hint = typedef.display_hint.clone();
            td.description = typedef.description.clone();
            td.reference = typedef.reference.clone();
            td.is_tc = typedef.is_textual_convention;

            // Extract constraints and named values from syntax.
            extract_type_values(&typedef.syntax, &mut td);

            let type_id = ctx.mib.add_type(td);
            ctx.module_symbol_to_type
                .entry(ir_id)
                .or_default()
                .insert(typedef.name.clone(), type_id);
            ctx.mib
                .module_mut(resolved_id)
                .add_type(&typedef.name, type_id);
        }
    }
}

/// Determine the base type from syntax.
pub(super) fn syntax_to_base_type(syntax: &ir::TypeSyntax) -> BaseType {
    match syntax {
        ir::TypeSyntax::IntegerEnum { .. } => BaseType::Integer32,
        ir::TypeSyntax::Bits { .. } => BaseType::Bits,
        ir::TypeSyntax::OctetString => BaseType::OctetString,
        ir::TypeSyntax::ObjectIdentifier => BaseType::ObjectIdentifier,
        ir::TypeSyntax::Constrained { base, .. } => syntax_to_base_type(base),
        ir::TypeSyntax::SequenceOf { .. } => BaseType::Unknown,
        ir::TypeSyntax::Sequence { .. } => BaseType::Unknown,
        ir::TypeSyntax::TypeRef { name, .. } => match name.as_str() {
            "INTEGER" => BaseType::Integer32,
            "OCTET STRING" => BaseType::OctetString,
            "OBJECT IDENTIFIER" => BaseType::ObjectIdentifier,
            "BITS" => BaseType::Bits,
            _ => BaseType::Unknown,
        },
    }
}

/// Extract named values (enums, bits) and constraints (sizes, ranges) from syntax.
fn extract_type_values(syntax: &ir::TypeSyntax, td: &mut TypeData) {
    match syntax {
        ir::TypeSyntax::IntegerEnum { named_numbers, .. } => {
            td.enums = named_numbers
                .iter()
                .map(|nn| NamedValue {
                    label: nn.name.clone(),
                    value: nn.value,
                    span: nn.span,
                })
                .collect();
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            td.bits = named_bits
                .iter()
                .map(|nb| NamedValue {
                    label: nb.name.clone(),
                    value: nb.position as i64,
                    span: nb.span,
                })
                .collect();
        }
        ir::TypeSyntax::Constrained {
            base, constraint, ..
        } => {
            extract_type_values(base, td);
            extract_constraint(constraint, td);
        }
        _ => {}
    }
}

fn extract_constraint(constraint: &ir::Constraint, td: &mut TypeData) {
    match constraint {
        ir::Constraint::Size { ranges, .. } => {
            td.sizes = ranges.iter().filter_map(resolve_range).collect();
        }
        ir::Constraint::Range { ranges, .. } => {
            td.ranges = ranges.iter().filter_map(resolve_range).collect();
        }
    }
}

pub(super) fn resolve_range(r: &ir::syntax::Range) -> Option<Range> {
    let min = range_value_to_i64(&r.min)?;
    let max = match &r.max {
        Some(v) => range_value_to_i64(v)?,
        None => min,
    };
    Some(Range {
        min,
        max,
        span: r.span,
    })
}

fn range_value_to_i64(v: &ir::syntax::RangeValue) -> Option<i64> {
    match v {
        ir::syntax::RangeValue::Signed(n) => Some(*n),
        ir::syntax::RangeValue::Unsigned(n) => {
            if *n > i64::MAX as u64 {
                Some(i64::MAX)
            } else {
                Some(*n as i64)
            }
        }
        ir::syntax::RangeValue::Min => Some(i64::MIN),
        ir::syntax::RangeValue::Max => Some(i64::MAX),
    }
}

/// Resolve type parents and inherit base types.
fn resolve_type_bases(ctx: &mut ResolverContext) {
    resolve_type_ref_parents_graph(ctx);
    link_primitive_syntax_parents(ctx);
    link_rfc1213_types_to_tcs(ctx);
    inherit_base_types(ctx);
}

/// Build a dependency graph of types and resolve parent references in topo order.
fn resolve_type_ref_parents_graph(ctx: &mut ResolverContext) {
    // Build graph: type_id -> parent type name reference.
    let mut type_to_parent_ref: Vec<(TypeId, IrModuleId, String, Span)> = Vec::new();

    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let m = &ctx.modules[idx];
        for def in &m.definitions {
            let typedef = match def {
                ir::Definition::TypeDef(td) => td,
                _ => continue,
            };
            if matches!(typedef.syntax, ir::TypeSyntax::Sequence { .. }) {
                continue;
            }

            let type_ref_name = extract_type_ref_name(&typedef.syntax);
            if let Some(ref_name) = type_ref_name
                && let Some(&type_id) = ctx
                    .module_symbol_to_type
                    .get(&ir_id)
                    .and_then(|m| m.get(&typedef.name))
            {
                type_to_parent_ref.push((
                    type_id,
                    ir_id,
                    ref_name.to_string(),
                    typedef.syntax.span(),
                ));
            }
        }
    }

    // Build petgraph for topological ordering.
    let mut g = graph::Graph::new();
    let mut type_id_to_graph_node: HashMap<TypeId, graph::NodeIndex> = HashMap::new();
    let mut graph_symbol_to_type_id: HashMap<graph::Symbol, TypeId> = HashMap::new();

    // Add all type nodes.
    for (&ir_id, type_map) in &ctx.module_symbol_to_type {
        let mod_name = &ctx.modules[ir_id.0 as usize].name;
        for (name, &type_id) in type_map {
            let gn = g.add_node(graph::Symbol {
                module: mod_name.clone(),
                name: name.clone(),
            });
            graph_symbol_to_type_id.insert(
                graph::Symbol {
                    module: mod_name.clone(),
                    name: name.clone(),
                },
                type_id,
            );
            type_id_to_graph_node.insert(type_id, gn);
        }
    }

    // Add edges (child -> parent).
    for (type_id, ir_id, ref_name, _span) in &type_to_parent_ref {
        let child_gn = match type_id_to_graph_node.get(type_id) {
            Some(&gn) => gn,
            None => continue,
        };

        // Look up the parent type.
        if let Some((parent_type_id, _used_import)) = ctx.lookup_type_for_module(*ir_id, ref_name)
            && let Some(&parent_gn) = type_id_to_graph_node.get(&parent_type_id)
        {
            g.add_edge(child_gn, parent_gn);
        }
    }

    // Topological sort.
    let result = g.resolution_order();

    // Log cycles.
    if enabled!(target: "mib_rs::resolver", Level::TRACE) {
        for cycle in &result.cycles {
            let names: Vec<String> = cycle
                .iter()
                .map(|s| format!("{}::{}", s.module, s.name))
                .collect();
            trace!(
                target: "mib_rs::resolver",
                component = "resolver",
                phase = "types",
                cycle_path = %names.join(" -> "),
                "type dependency cycle",
            );
        }
    }

    // Record unresolved diagnostics for cycle members (gomib parity).
    let parent_ref_by_type: HashMap<TypeId, (IrModuleId, String, Span)> = type_to_parent_ref
        .iter()
        .map(|(tid, ir_id, ref_name, span)| (*tid, (*ir_id, ref_name.clone(), *span)))
        .collect();
    for cycle in &result.cycles {
        for sym in cycle {
            let Some(&tid) = graph_symbol_to_type_id.get(sym) else {
                continue;
            };
            let Some((ir_id, ref_name, span)) = parent_ref_by_type.get(&tid) else {
                continue;
            };
            let mod_name = ctx.modules[ir_id.0 as usize].name.clone();
            ctx.record_unresolved_type(ref_name, &mod_name, *ir_id, *span);
        }
    }

    // Resolve parents in topological order (reversed since children depend on parents).
    // We need to map graph nodes back to type IDs.
    let graph_node_to_type: HashMap<graph::NodeIndex, TypeId> = type_id_to_graph_node
        .iter()
        .map(|(&tid, &gn)| (gn, tid))
        .collect();

    for gn in result.order_indices.iter().rev() {
        let type_id = match graph_node_to_type.get(gn) {
            Some(&tid) => tid,
            None => continue,
        };

        // Find the parent ref for this type.
        let parent_info = type_to_parent_ref
            .iter()
            .find(|(tid, _, _, _)| *tid == type_id);

        if let Some((_, ir_id, ref_name, span)) = parent_info {
            if let Some((parent_type_id, used_import)) =
                ctx.lookup_type_for_module(*ir_id, ref_name)
            {
                if parent_type_id != type_id {
                    ctx.mib.type_mut(type_id).parent = Some(parent_type_id);
                    if used_import {
                        ctx.mark_import_used(*ir_id, ref_name);
                    }
                }
            } else {
                ctx.record_unresolved_type(
                    ref_name,
                    &ctx.modules[ir_id.0 as usize].name.clone(),
                    *ir_id,
                    *span,
                );
            }
        }
    }
}

/// Extract the type reference name from a type syntax (the name being referenced).
fn extract_type_ref_name(syntax: &ir::TypeSyntax) -> Option<&str> {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => {
            // Don't follow references to ASN.1 primitives that are already seeded.
            if matches!(
                name.as_str(),
                "INTEGER" | "OCTET STRING" | "OBJECT IDENTIFIER" | "BITS"
            ) {
                None
            } else {
                Some(name)
            }
        }
        ir::TypeSyntax::Constrained { base, .. } => extract_type_ref_name(base),
        _ => None,
    }
}

/// Collect SMI base type references from a syntax tree.
fn collect_syntax_base_type_refs(
    syntax: &ir::TypeSyntax,
    smi_base_types: &[&str],
    refs: &mut std::collections::HashSet<String>,
) {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => {
            if smi_base_types.contains(&name.as_str()) {
                refs.insert(name.clone());
            }
        }
        ir::TypeSyntax::Constrained { base, .. } => {
            collect_syntax_base_type_refs(base, smi_base_types, refs);
        }
        ir::TypeSyntax::IntegerEnum { base, .. } => {
            if !base.is_empty() && smi_base_types.contains(&base.as_str()) {
                refs.insert(base.clone());
            }
        }
        _ => {}
    }
}

/// Link types with primitive syntax (OCTET STRING {...}, INTEGER {...}, BITS)
/// to their corresponding primitive parent.
fn link_primitive_syntax_parents(ctx: &mut ResolverContext) {
    let smi_id = match ctx.snmpv2_smi {
        Some(id) => id,
        None => return,
    };

    let primitives = ["INTEGER", "OCTET STRING", "OBJECT IDENTIFIER", "BITS"];
    let mut prim_types: HashMap<BaseType, TypeId> = HashMap::new();
    for name in &primitives {
        if let Some(&tid) = ctx
            .module_symbol_to_type
            .get(&smi_id)
            .and_then(|m| m.get(*name))
        {
            let base = ctx.mib.type_(tid).base;
            prim_types.insert(base, tid);
        }
    }

    let type_count = ctx.mib.types_slice().len();
    for i in 0..type_count {
        let tid = TypeId::new(i as u32);
        let t = ctx.mib.type_(tid);
        if t.parent.is_some() {
            continue;
        }
        let base = t.base;
        if base == BaseType::Unknown {
            continue;
        }
        if let Some(&prim_id) = prim_types.get(&base)
            && prim_id != tid
        {
            ctx.mib.type_mut(tid).parent = Some(prim_id);
        }
    }
}

/// Link RFC1213-MIB's DisplayString and PhysAddress to SNMPv2-TC's versions.
fn link_rfc1213_types_to_tcs(ctx: &mut ResolverContext) {
    let tc_id = match ctx.snmpv2_tc {
        Some(id) => id,
        None => return,
    };

    let rfc1213_candidates = ctx.module_index.get("RFC1213-MIB").cloned();
    let rfc1213_id = match rfc1213_candidates.as_ref().and_then(|c| c.first()) {
        Some(&id) => id,
        None => return,
    };

    let links = [
        ("DisplayString", "DisplayString"),
        ("PhysAddress", "PhysAddress"),
    ];
    for (rfc_name, tc_name) in &links {
        let rfc_type = ctx
            .module_symbol_to_type
            .get(&rfc1213_id)
            .and_then(|m| m.get(*rfc_name))
            .copied();
        let tc_type = ctx
            .module_symbol_to_type
            .get(&tc_id)
            .and_then(|m| m.get(*tc_name))
            .copied();

        if let (Some(rfc_tid), Some(tc_tid)) = (rfc_type, tc_type) {
            ctx.mib.type_mut(rfc_tid).parent = Some(tc_tid);
        }
    }
}

/// Walk each type's parent chain to inherit the root base type.
fn inherit_base_types(ctx: &mut ResolverContext) {
    let type_count = ctx.mib.types_slice().len();
    for i in 0..type_count {
        let tid = TypeId::new(i as u32);
        let t = ctx.mib.type_(tid);
        if t.base != BaseType::Unknown {
            continue;
        }
        if let Some(inherited) = resolve_base_from_chain(ctx.mib.types_slice(), tid) {
            ctx.mib.type_mut(tid).base = inherited;
        }
    }
}

fn resolve_base_from_chain(types: &[TypeData], type_id: TypeId) -> Option<BaseType> {
    let mut current = Some(type_id);
    let mut depth = 0;
    while let Some(id) = current {
        if depth >= 1000 {
            break;
        }
        let t = &types[id.0 as usize];
        if t.base != BaseType::Unknown {
            return Some(t.base);
        }
        if is_application_base_type(t.base) {
            return Some(t.base);
        }
        current = t.parent;
        depth += 1;
    }
    None
}

fn is_application_base_type(b: BaseType) -> bool {
    matches!(
        b,
        BaseType::Counter32
            | BaseType::Counter64
            | BaseType::Gauge32
            | BaseType::Unsigned32
            | BaseType::TimeTicks
            | BaseType::IpAddress
            | BaseType::Opaque
    )
}

/// Validate that SMIv2 modules explicitly import SMI base types they reference.
pub(super) fn check_basetype_imports(ctx: &mut ResolverContext) {
    let smi_base_types = [
        "Integer32",
        "Counter32",
        "Counter64",
        "Gauge32",
        "Unsigned32",
        "TimeTicks",
        "IpAddress",
        "Opaque",
    ];

    let mut diagnostics = Vec::new();

    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let m = &ctx.modules[idx];

        if m.language != Language::SMIv2 {
            continue;
        }
        if crate::lower::base_modules::is_base_module(&m.name) {
            continue;
        }

        // Collect imported symbol names.
        let imported: std::collections::HashSet<&str> =
            m.imports.iter().map(|i| i.symbol.as_str()).collect();

        // Collect base types referenced in definitions.
        let mut referenced = std::collections::HashSet::new();
        for def in &m.definitions {
            let syntax = match def {
                ir::Definition::TypeDef(td) => &td.syntax,
                ir::Definition::ObjectType(ot) => &ot.syntax,
                _ => continue,
            };
            collect_syntax_base_type_refs(syntax, &smi_base_types, &mut referenced);
        }

        for ref_name in &referenced {
            if !imported.contains(ref_name.as_str()) {
                diagnostics.push((
                    ir_id,
                    m.span,
                    format!("SMIv2 module references {} without importing it", ref_name),
                ));
            }
        }
    }

    for (ir_id, span, message) in diagnostics {
        ctx.emit_diagnostic(DiagCode::BasetypeNotImported, Some(ir_id), span, message);
    }
}
