//! Phase 3: Type resolution.
//!
//! Builds the resolved type system in three steps:
//!
//! - Seed ASN.1 primitive types (INTEGER, OCTET STRING, OBJECT IDENTIFIER, BITS)
//!   in SNMPv2-SMI.
//! - Create resolved [`Type`](super::super::typedef::TypeData) entries for every
//!   TEXTUAL-CONVENTION and type assignment across all modules.
//! - Resolve parent chains using topological sort to handle dependencies, then
//!   inherit base types down the chain.
//!
//! Types involved in dependency cycles are recorded as unresolved with
//! appropriate diagnostics.

use std::collections::{HashMap, HashSet};

use tracing::{Level, enabled, trace};

use crate::graph;
use crate::ir;
use crate::source::SourceRange;
use crate::types::{BaseType, DiagCode, Language};

use super::super::typedef::TypeData;
use super::super::types::*;
use super::context::{IrModuleId, ResolverContext, UnresolvedReason};

/// Recover semantic kinds for application-tagged types in foundation modules.
///
/// Lowering intentionally discards ASN.1 tags, so the underlying INTEGER or
/// OCTET STRING syntax alone cannot distinguish these well-known SMI types.
fn foundation_base_type(name: &str) -> Option<BaseType> {
    match name {
        "Integer32" => Some(BaseType::Integer32),
        "Counter" | "Counter32" => Some(BaseType::Counter32),
        "Counter64" => Some(BaseType::Counter64),
        "Gauge" | "Gauge32" => Some(BaseType::Gauge32),
        "Unsigned32" => Some(BaseType::Unsigned32),
        "TimeTicks" => Some(BaseType::TimeTicks),
        "IpAddress" | "NetworkAddress" => Some(BaseType::IpAddress),
        "Opaque" => Some(BaseType::Opaque),
        _ => None,
    }
}

/// RFC-derived descriptions for primitive and application types whose plain
/// ASN.1 assignments cannot carry DESCRIPTION clauses.
fn foundation_type_description(name: &str) -> Option<&'static str> {
    match name {
        "INTEGER" => Some("An arbitrary precision integer value."),
        "OCTET STRING" => Some("An ordered sequence of zero or more octets."),
        "OBJECT IDENTIFIER" => Some(
            "An administratively assigned name identifying an object type or registration point.",
        ),
        "BITS" => Some("A named collection of individual bit positions."),
        "Integer32" => {
            Some("An integer-valued type restricted to the range -2147483648 to 2147483647.")
        }
        "IpAddress" => Some(
            "A 32-bit internet address represented as an OCTET STRING of length 4 in network byte-order.",
        ),
        "Counter" | "Counter32" => Some(
            "A non-negative integer that monotonically increases to a maximum of 4294967295, then wraps to zero.",
        ),
        "Gauge32" => Some(
            "A non-negative integer that may increase or decrease, but never exceeds 4294967295 or falls below zero.",
        ),
        "Gauge" => Some(
            "A non-negative integer that may increase or decrease, but latches at a maximum of 4294967295.",
        ),
        "Unsigned32" => {
            Some("An unsigned integer-valued type restricted to the range 0 to 4294967295.")
        }
        "TimeTicks" => {
            Some("A non-negative integer counting hundredths of a second between two epochs.")
        }
        "Opaque" => Some(
            "An arbitrary ASN.1 value double-wrapped as an OCTET STRING. Provided for backward-compatibility only.",
        ),
        "Counter64" => Some(
            "A non-negative integer that monotonically increases to a maximum of 18446744073709551615, then wraps to zero.",
        ),
        "NetworkAddress" => Some("An address from one of possibly several protocol families."),
        _ => None,
    }
}

/// Phase 3: Build the type system.
///
/// Seeds primitive types, creates user-defined types, then resolves parent
/// chains and inherits base types through the type graph.
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
        td.description = foundation_type_description(name)
            .unwrap_or_default()
            .to_string();
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

        let m = &ctx.modules[ir_id.index()];
        for def in &m.definitions {
            let typedef = match def {
                ir::Definition::TypeDef(td) => td,
                _ => continue,
            };

            // Skip SEQUENCE type assignments (they are structural, not type definitions).
            if matches!(typedef.syntax, ir::TypeSyntax::Sequence { .. }) {
                continue;
            }

            let mut base = if let Some(bt) = typedef.base_type {
                bt
            } else {
                syntax_to_base_type(&typedef.syntax)
            };
            if crate::lower::base_modules::is_base_module(&m.name)
                && let Some(application_base) = foundation_base_type(&typedef.name)
            {
                base = application_base;
            }

            let mut td = TypeData::new(typedef.name.clone());
            td.range = Some(typedef.range);
            td.syntax_range = Some(typedef.syntax_range);
            td.module = Some(resolved_id);
            td.base = base;
            td.status = typedef.status;
            td.hint = typedef.display_hint.clone();
            td.description = typedef.description.clone();
            if td.description.is_empty()
                && crate::lower::base_modules::is_base_module(&m.name)
                && let Some(description) = foundation_type_description(&typedef.name)
            {
                td.description = description.to_string();
            }
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

/// Determine the [`BaseType`] from an IR type syntax node.
///
/// Recursively unwraps constrained types and resolves type references
/// through well-known name mappings via [`base_type_from_name`]. Returns
/// [`BaseType::Unknown`] for unrecognized or structural types (SEQUENCE,
/// SEQUENCE OF).
pub(super) fn syntax_to_base_type(syntax: &ir::TypeSyntax) -> BaseType {
    match syntax {
        ir::TypeSyntax::IntegerEnum { base, .. } if !base.is_empty() => BaseType::Unknown,
        ir::TypeSyntax::IntegerEnum { .. } => BaseType::Integer32,
        ir::TypeSyntax::Bits { .. } => BaseType::Bits,
        ir::TypeSyntax::OctetString { .. } => BaseType::OctetString,
        ir::TypeSyntax::ObjectIdentifier { .. } => BaseType::ObjectIdentifier,
        ir::TypeSyntax::Constrained { base, .. } => syntax_to_base_type(base),
        ir::TypeSyntax::SequenceOf { .. } | ir::TypeSyntax::Sequence { .. } => BaseType::Unknown,
        ir::TypeSyntax::TypeRef { name, .. } => base_type_from_name(name),
    }
}

/// Map a well-known type name to its [`BaseType`], or [`BaseType::Unknown`] if not recognized.
///
/// Handles ASN.1 primitives (INTEGER, OCTET STRING, etc.), SMIv2 application
/// types (Counter32, Gauge32, etc.), and their SMIv1 aliases (Counter, Gauge).
pub(crate) fn base_type_from_name(name: &str) -> BaseType {
    match name {
        "INTEGER" | "Integer32" => BaseType::Integer32,
        "OCTET STRING" => BaseType::OctetString,
        "OBJECT IDENTIFIER" | "ObjectName" | "NotificationName" => BaseType::ObjectIdentifier,
        "BITS" => BaseType::Bits,
        "Counter" | "Counter32" => BaseType::Counter32,
        "Counter64" => BaseType::Counter64,
        "Gauge" | "Gauge32" => BaseType::Gauge32,
        "Unsigned32" => BaseType::Unsigned32,
        "TimeTicks" => BaseType::TimeTicks,
        "IpAddress" | "NetworkAddress" => BaseType::IpAddress,
        "Opaque" => BaseType::Opaque,
        _ => BaseType::Unknown,
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
                    range: nn.range,
                })
                .collect();
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            td.bits = named_bits
                .iter()
                .map(|nb| NamedValue {
                    label: nb.name.clone(),
                    value: nb.position as i64,
                    range: nb.range,
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
            td.sizes = ranges.iter().map(resolve_range).collect();
        }
        ir::Constraint::Range { ranges, .. } => {
            td.ranges = ranges.iter().map(resolve_range).collect();
        }
    }
}

/// Convert an IR range constraint to the resolved [`Range`] type without
/// narrowing unsigned literals or inventing values for `MIN` and `MAX`.
///
/// Used by both the type phase and the semantics phase (for inline
/// OBJECT-TYPE constraints).
pub(super) fn resolve_range(r: &ir::syntax::Range) -> Range {
    let min = resolve_range_bound(&r.min);
    let max = r
        .max
        .as_ref()
        .map(resolve_range_bound)
        .unwrap_or_else(|| min.clone());
    Range {
        min,
        max,
        range: Some(r.range),
    }
}

fn resolve_range_bound(v: &ir::syntax::RangeValue) -> RangeBound {
    match v {
        ir::syntax::RangeValue::Signed(value) => RangeBound::Signed(*value),
        ir::syntax::RangeValue::Unsigned(value) => RangeBound::Unsigned(*value),
        ir::syntax::RangeValue::Min => RangeBound::Min,
        ir::syntax::RangeValue::Max => RangeBound::Max,
        ir::syntax::RangeValue::Raw(value) => RangeBound::Raw(value.clone()),
    }
}

/// Resolve type parents and inherit base types.
fn resolve_type_bases(ctx: &mut ResolverContext) {
    let cycle_type_ids = resolve_type_ref_parents_graph(ctx);
    link_primitive_syntax_parents(ctx, &cycle_type_ids);
    link_rfc1213_types_to_tcs(ctx, &cycle_type_ids);
    inherit_base_types(ctx);
    normalize_named_values_for_base(ctx);
    compute_effective_constraints(ctx);
}

/// The grammar represents a named refinement of a referenced type with the
/// same node used for INTEGER enumerations. Once parent bases are known, move
/// those direct values to BITS when the referenced type is BITS-based.
fn normalize_named_values_for_base(ctx: &mut ResolverContext) {
    for index in 0..ctx.mib.types_slice().len() {
        let type_id = TypeId::new(index as u32);
        let typ = ctx.mib.raw().type_(type_id);
        if typ.base != BaseType::Bits || typ.enums.is_empty() || !typ.bits.is_empty() {
            continue;
        }
        let values = std::mem::take(&mut ctx.mib.type_mut(type_id).enums);
        ctx.mib.type_mut(type_id).bits = values;
    }
}

/// Build a dependency graph of types and resolve parent references in topo order.
fn resolve_type_ref_parents_graph(ctx: &mut ResolverContext) -> HashSet<TypeId> {
    // Build graph: type_id -> parent type name reference.
    let mut type_to_parent_ref: Vec<(TypeId, IrModuleId, String, SourceRange)> = Vec::new();

    for (ir_id, m) in ctx.all_modules() {
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
                    typedef.syntax.range(),
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
        let mod_name = &ctx.modules[ir_id.index()].name;
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

    // Record cycle members as unresolved and leave their parent links unset.
    let cycle_type_ids: HashSet<TypeId> = result
        .cycles
        .iter()
        .flatten()
        .filter_map(|sym| graph_symbol_to_type_id.get(sym).copied())
        .collect();
    let parent_ref_by_type: HashMap<TypeId, (IrModuleId, String, SourceRange)> = type_to_parent_ref
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
            let mod_name = ctx.modules[ir_id.index()].name.clone();
            let type_name = ctx.mib.raw().type_(tid).name().to_string();
            if ctx
                .lookup_type_for_module(*ir_id, ref_name)
                .is_some_and(|(_, used_import)| used_import)
            {
                ctx.mark_import_used(*ir_id, ref_name);
            }
            ctx.record_unresolved_type(
                &type_name,
                ref_name,
                &mod_name,
                UnresolvedReason::DependencyCycle,
                *ir_id,
                *span,
            );
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
        if cycle_type_ids.contains(&type_id) {
            continue;
        }

        if let Some((ir_id, ref_name, span)) = parent_ref_by_type.get(&type_id) {
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
                let type_name = ctx.mib.raw().type_(type_id).name().to_string();
                let mod_name = ctx.modules[ir_id.index()].name.clone();
                ctx.record_unresolved_type(
                    &type_name,
                    ref_name,
                    &mod_name,
                    UnresolvedReason::TypeNotFound,
                    *ir_id,
                    *span,
                );
            }
        }
    }

    cycle_type_ids
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
        ir::TypeSyntax::IntegerEnum { base, .. } if !base.is_empty() => Some(base),
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
        ir::TypeSyntax::IntegerEnum { base, .. }
            if !base.is_empty() && smi_base_types.contains(&base.as_str()) =>
        {
            refs.insert(base.clone());
        }
        _ => {}
    }
}

/// Link types with primitive syntax (OCTET STRING {...}, INTEGER {...}, BITS)
/// to their corresponding primitive parent.
fn link_primitive_syntax_parents(ctx: &mut ResolverContext, cycle_type_ids: &HashSet<TypeId>) {
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
            let base = ctx.mib.raw().type_(tid).base;
            prim_types.insert(base, tid);
        }
    }

    let type_count = ctx.mib.types_slice().len();
    for i in 0..type_count {
        let tid = TypeId::new(i as u32);
        let t = ctx.mib.raw().type_(tid);
        if t.parent.is_some() || cycle_type_ids.contains(&tid) {
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
fn link_rfc1213_types_to_tcs(ctx: &mut ResolverContext, cycle_type_ids: &HashSet<TypeId>) {
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

        if let (Some(rfc_tid), Some(tc_tid)) = (rfc_type, tc_type)
            && !cycle_type_ids.contains(&rfc_tid)
        {
            ctx.mib.type_mut(rfc_tid).parent = Some(tc_tid);
        }
    }
}

/// Walk each type's parent chain to inherit the root base type.
fn inherit_base_types(ctx: &mut ResolverContext) {
    let type_count = ctx.mib.types_slice().len();
    for i in 0..type_count {
        let tid = TypeId::new(i as u32);
        let t = ctx.mib.raw().type_(tid);
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
        let t = &types[id.index() as usize];
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

fn compute_effective_constraints(ctx: &mut ResolverContext) {
    let inputs: Vec<_> = ctx
        .mib
        .types_slice()
        .iter()
        .map(|typ| (typ.sizes.clone(), typ.ranges.clone(), typ.parent, typ.base))
        .collect();
    let mut resolved = vec![None; inputs.len()];

    for index in 0..inputs.len() {
        resolve_effective_constraints(index, &inputs, &mut resolved, 0);
    }
    for (index, constraints) in resolved.into_iter().enumerate() {
        let (sizes, ranges) = constraints.unwrap_or_default();
        let typ = ctx.mib.type_mut(TypeId::new(index as u32));
        typ.effective_sizes = sizes.values;
        typ.effective_ranges = ranges.values;
        typ.effective_sizes_constrained = sizes.present;
        typ.effective_ranges_constrained = ranges.present;
    }
}

#[derive(Clone, Default)]
struct EffectiveConstraint {
    values: Vec<Range>,
    present: bool,
}

#[allow(clippy::type_complexity)]
fn resolve_effective_constraints(
    index: usize,
    inputs: &[(Vec<Range>, Vec<Range>, Option<TypeId>, BaseType)],
    resolved: &mut [Option<(EffectiveConstraint, EffectiveConstraint)>],
    depth: usize,
) -> (EffectiveConstraint, EffectiveConstraint) {
    if let Some(constraints) = &resolved[index] {
        return constraints.clone();
    }
    let (own_sizes, own_ranges, parent, base) = &inputs[index];
    let (mut parent_sizes, mut parent_ranges) = if depth < 1000 {
        parent
            .map(|parent_id| {
                resolve_effective_constraints(
                    parent_id.index() as usize,
                    inputs,
                    resolved,
                    depth + 1,
                )
            })
            .unwrap_or_default()
    } else {
        (
            EffectiveConstraint::default(),
            EffectiveConstraint::default(),
        )
    };
    if !parent_sizes.present
        && !own_sizes.is_empty()
        && let Some(range) = base_constraint(*base, true)
    {
        parent_sizes = EffectiveConstraint {
            values: vec![range],
            present: true,
        };
    }
    if !parent_ranges.present
        && !own_ranges.is_empty()
        && let Some(range) = base_constraint(*base, false)
    {
        parent_ranges = EffectiveConstraint {
            values: vec![range],
            present: true,
        };
    }
    let constraints = (
        effective_constraints(own_sizes, &parent_sizes),
        effective_constraints(own_ranges, &parent_ranges),
    );
    resolved[index] = Some(constraints.clone());
    constraints
}

pub(super) fn base_constraint(base: BaseType, is_size: bool) -> Option<Range> {
    let (min, max) = if is_size {
        (RangeBound::Unsigned(0), RangeBound::Unsigned(65535))
    } else {
        match base {
            BaseType::Integer32 => (
                RangeBound::Signed(i64::from(i32::MIN)),
                RangeBound::Signed(i64::from(i32::MAX)),
            ),
            BaseType::Unsigned32
            | BaseType::Gauge32
            | BaseType::TimeTicks
            | BaseType::Counter32 => (
                RangeBound::Unsigned(0),
                RangeBound::Unsigned(u64::from(u32::MAX)),
            ),
            BaseType::Counter64 => (RangeBound::Unsigned(0), RangeBound::Unsigned(u64::MAX)),
            _ => return None,
        }
    };
    Some(Range {
        min,
        max,
        range: None,
    })
}

fn effective_constraints(own: &[Range], parent: &EffectiveConstraint) -> EffectiveConstraint {
    if own.is_empty() {
        return parent.clone();
    }
    if !parent.present {
        return EffectiveConstraint {
            values: own.to_vec(),
            present: true,
        };
    }
    EffectiveConstraint {
        values: if parent.values.is_empty() {
            Vec::new()
        } else {
            intersect_constraints(own, &parent.values)
        },
        present: true,
    }
}

pub(super) fn intersect_constraints(own: &[Range], parent: &[Range]) -> Vec<Range> {
    if own.is_empty() {
        return Vec::new();
    }
    if parent.is_empty() {
        return own.to_vec();
    }

    let mut result = Vec::with_capacity(own.len() * parent.len());
    for child in own {
        for (index, parent_alternative) in parent.iter().enumerate() {
            let Some(child_min) =
                resolve_child_range_bound(&child.min, parent_alternative, parent, index, true)
            else {
                continue;
            };
            let Some(child_max) =
                resolve_child_range_bound(&child.max, parent_alternative, parent, index, false)
            else {
                continue;
            };

            // Comparing every known lower candidate with every known upper
            // candidate can prove an intersection empty even when another
            // endpoint is unresolved.
            if any_range_bound_greater(
                [&parent_alternative.min, &child_min],
                [&parent_alternative.max, &child_max],
            ) {
                continue;
            }

            result.push(Range {
                min: max_range_bound(&child_min, &parent_alternative.min),
                max: min_range_bound(&child_max, &parent_alternative.max),
                range: child.range,
            });
        }
    }
    result
}

// Resolve a symbolic child endpoint for one parent alternative. A lower MIN
// and upper MAX do not constrain an alternative. A lower MAX or upper MIN only
// applies to alternatives which could contain that global parent extreme.
fn resolve_child_range_bound(
    bound: &RangeBound,
    alternative: &Range,
    parent: &[Range],
    index: usize,
    lower: bool,
) -> Option<RangeBound> {
    if lower {
        match bound {
            RangeBound::Min => return Some(alternative.min.clone()),
            RangeBound::Max => {
                return could_contain_global_max(parent, index).then(|| alternative.max.clone());
            }
            _ => {}
        }
    } else {
        match bound {
            RangeBound::Max => return Some(alternative.max.clone()),
            RangeBound::Min => {
                return could_contain_global_min(parent, index).then(|| alternative.min.clone());
            }
            _ => {}
        }
    }
    Some(bound.clone())
}

fn could_contain_global_max(ranges: &[Range], index: usize) -> bool {
    let candidate = &ranges[index].max;
    ranges.iter().enumerate().all(|(other_index, other)| {
        other_index == index
            || !other
                .max
                .cmp_value(candidate)
                .is_some_and(|comparison| comparison.is_gt())
                // A greater known minimum proves that the other maximum must
                // also be greater even if that maximum is unresolved.
                && !other
                    .min
                    .cmp_value(candidate)
                    .is_some_and(|comparison| comparison.is_gt())
    })
}

fn could_contain_global_min(ranges: &[Range], index: usize) -> bool {
    let candidate = &ranges[index].min;
    ranges.iter().enumerate().all(|(other_index, other)| {
        other_index == index
            || !other
                .min
                .cmp_value(candidate)
                .is_some_and(|comparison| comparison.is_lt())
                // A lesser known maximum proves that the other minimum must
                // also be lesser even if that minimum is unresolved.
                && !other
                    .max
                    .cmp_value(candidate)
                    .is_some_and(|comparison| comparison.is_lt())
    })
}

fn any_range_bound_greater(lowers: [&RangeBound; 2], uppers: [&RangeBound; 2]) -> bool {
    lowers.into_iter().any(|lower| {
        uppers.iter().any(|upper| {
            lower
                .cmp_value(upper)
                .is_some_and(|comparison| comparison.is_gt())
        })
    })
}

fn max_range_bound(left: &RangeBound, right: &RangeBound) -> RangeBound {
    match left.cmp_value(right) {
        Some(comparison) if comparison.is_lt() => right.clone(),
        Some(_) => left.clone(),
        None => unresolved_range_bound(left, right),
    }
}

fn min_range_bound(left: &RangeBound, right: &RangeBound) -> RangeBound {
    match left.cmp_value(right) {
        Some(comparison) if comparison.is_gt() => right.clone(),
        Some(_) => left.clone(),
        None => unresolved_range_bound(left, right),
    }
}

// Preserve the raw endpoint when an exact min/max cannot be represented. If
// both operands are raw, consistently prefer the child-side operand (`left`).
fn unresolved_range_bound(left: &RangeBound, right: &RangeBound) -> RangeBound {
    if matches!(left, RangeBound::Raw(_)) {
        left.clone()
    } else {
        right.clone()
    }
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
///
/// Per RFC 2578, application types like Counter32, Gauge32, etc. must be
/// explicitly imported from SNMPv2-SMI. Emits [`DiagCode::BasetypeNotImported`]
/// when a module uses these types without importing them.
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

    for (ir_id, m) in ctx.user_modules() {
        if m.language != Language::SMIv2 {
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
                    m.range,
                    format!(
                        "{} used but not imported from SNMPv2-SMI in {}",
                        ref_name, m.name
                    ),
                ));
            }
        }
    }

    for (ir_id, range, message) in diagnostics {
        ctx.emit_diagnostic(DiagCode::BasetypeNotImported, Some(ir_id), range, message);
    }
}
