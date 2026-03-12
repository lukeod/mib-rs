use std::collections::HashSet;

use tracing::trace;

use crate::graph;
use crate::ir;
use crate::lower::base_modules;
use crate::types::{Kind, Span};

use super::super::types::*;
use super::context::{IrModuleId, ResolverContext, UnresolvedReason};
use super::util::{language_rank, normalize_timestamp};

/// An OID definition collected for resolution.
struct OidDef {
    ir_mod: IrModuleId,
    def_idx: usize,
    symbol: graph::Symbol,
    kind: OidDefKind,
}

impl OidDef {
    fn name(&self) -> &str {
        &self.symbol.name
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OidDefKind {
    ObjectType,
    ModuleIdentity,
    ObjectIdentity,
    Notification,
    ValueAssignment,
    ObjectGroup,
    NotificationGroup,
    ModuleCompliance,
    AgentCapabilities,
}

impl OidDefKind {
    fn to_node_kind(self) -> Kind {
        match self {
            OidDefKind::ObjectType => Kind::Scalar, // refined later
            OidDefKind::ModuleIdentity => Kind::ModuleIdentity,
            OidDefKind::ObjectIdentity => Kind::ObjectIdentity,
            OidDefKind::Notification => Kind::Notification,
            OidDefKind::ValueAssignment => Kind::Node,
            OidDefKind::ObjectGroup => Kind::Group,
            OidDefKind::NotificationGroup => Kind::Group,
            OidDefKind::ModuleCompliance => Kind::Compliance,
            OidDefKind::AgentCapabilities => Kind::Capability,
        }
    }
}

/// Phase 4: Build the OID trie from symbolic OID references.
pub(super) fn resolve_oids(ctx: &mut ResolverContext) {
    let (oid_defs, trap_defs) = collect_oid_definitions(ctx);

    // Build dependency graph.
    let mut g = graph::Graph::with_capacity(oid_defs.len());
    let mut def_to_gn: Vec<graph::NodeIndex> = Vec::with_capacity(oid_defs.len());
    let mut sym_to_gn_idx: std::collections::HashMap<graph::Symbol, usize> =
        std::collections::HashMap::with_capacity(oid_defs.len());

    for (i, od) in oid_defs.iter().enumerate() {
        let sym = graph::Symbol {
            module: od.symbol.module.clone(),
            name: od.symbol.name.clone(),
        };
        let gn = g.add_node(sym.clone());
        def_to_gn.push(gn);
        sym_to_gn_idx.insert(sym, i);
    }

    // Add edges based on first OID component.
    for (i, od) in oid_defs.iter().enumerate() {
        let m = &ctx.modules[od.ir_mod.index()];
        let oid = get_oid_assignment(m, od.def_idx);
        if let Some(oid_assign) = oid
            && let Some(first) = oid_assign.components.first()
            && let Some(dep_sym) = first_component_dep_symbol(ctx, od.ir_mod, first)
            && let Some(target_idx) = sym_to_gn_idx.get(&dep_sym)
        {
            g.add_edge(def_to_gn[i], def_to_gn[*target_idx]);
        }
    }

    // Topological sort.
    let result = g.resolution_order();

    // Record cycle members as unresolved.
    let cycle_symbols: HashSet<graph::Symbol> = result.cycles.iter().flatten().cloned().collect();

    let cycle_unresolved: Vec<_> = oid_defs
        .iter()
        .filter(|od| cycle_symbols.contains(&od.symbol))
        .map(|od| {
            let m = &ctx.modules[od.ir_mod.index()];
            let span = get_def_span(m, od.def_idx);
            (od.symbol.name.clone(), m.name.clone(), od.ir_mod, span)
        })
        .collect();
    if !result.cycles.is_empty() {
        trace!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "oids",
            cycle_count = result.cycles.len(),
            unresolved_oid_count = cycle_unresolved.len(),
            "detected oid dependency cycles",
        );
    }
    for (name, mod_name, ir_mod, span) in cycle_unresolved {
        ctx.record_unresolved_oid(
            &name,
            &name,
            &mod_name,
            UnresolvedReason::DependencyCycle,
            ir_mod,
            span,
        );
    }

    // Map graph nodes back to OidDef indices.
    let gn_to_idx: std::collections::HashMap<graph::NodeIndex, usize> = def_to_gn
        .iter()
        .enumerate()
        .map(|(i, &gn)| (gn, i))
        .collect();

    // Resolve definitions in topological order.
    for &gn in &result.order_indices {
        let idx = match gn_to_idx.get(&gn) {
            Some(&i) => i,
            None => continue,
        };
        let od = &oid_defs[idx];
        if cycle_symbols.contains(&od.symbol) {
            continue;
        }
        try_resolve_oid_definition(ctx, od);
    }

    // Resolve TRAP-TYPE definitions separately.
    resolve_trap_type_definitions(ctx, &trap_defs);
}

fn collect_oid_definitions(ctx: &mut ResolverContext) -> (Vec<OidDef>, Vec<OidDef>) {
    let mut oid_defs = Vec::new();
    let mut trap_defs = Vec::new();
    let mut notif_without_oid: Vec<(IrModuleId, Span, String)> = Vec::new();

    for (ir_id, m) in ctx.all_modules() {
        for (def_idx, def) in m.definitions.iter().enumerate() {
            match def {
                ir::Definition::ObjectType(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::ObjectType,
                    });
                }
                ir::Definition::ModuleIdentity(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::ModuleIdentity,
                    });
                }
                ir::Definition::ObjectIdentity(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::ObjectIdentity,
                    });
                }
                ir::Definition::Notification(d) => {
                    if d.trap_info.is_some() && d.oid.is_none() {
                        // TRAP-TYPE without OID - handle separately.
                        trap_defs.push(OidDef {
                            ir_mod: ir_id,
                            def_idx,
                            symbol: graph::Symbol {
                                module: m.name.clone(),
                                name: d.name.clone(),
                            },
                            kind: OidDefKind::Notification,
                        });
                    } else if d.oid.is_some() {
                        oid_defs.push(OidDef {
                            ir_mod: ir_id,
                            def_idx,
                            symbol: graph::Symbol {
                                module: m.name.clone(),
                                name: d.name.clone(),
                            },
                            kind: OidDefKind::Notification,
                        });
                    } else {
                        notif_without_oid.push((ir_id, d.span, d.name.clone()));
                    }
                }
                ir::Definition::ValueAssignment(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::ValueAssignment,
                    });
                }
                ir::Definition::ObjectGroup(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::ObjectGroup,
                    });
                }
                ir::Definition::NotificationGroup(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::NotificationGroup,
                    });
                }
                ir::Definition::ModuleCompliance(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::ModuleCompliance,
                    });
                }
                ir::Definition::AgentCapabilities(d) => {
                    oid_defs.push(OidDef {
                        ir_mod: ir_id,
                        def_idx,
                        symbol: graph::Symbol {
                            module: m.name.clone(),
                            name: d.name.clone(),
                        },
                        kind: OidDefKind::AgentCapabilities,
                    });
                }
                ir::Definition::TypeDef(_) => {} // skip types
            }
        }
    }

    for (ir_id, span, name) in notif_without_oid {
        ctx.emit_diagnostic(
            crate::types::DiagCode::NotifNoOid,
            Some(ir_id),
            span,
            format!("notification {:?} has no OID or trap info", name),
        );
    }

    (oid_defs, trap_defs)
}

fn get_oid_assignment(m: &ir::Module, def_idx: usize) -> Option<&ir::OidAssignment> {
    m.definitions[def_idx].oid()
}

fn get_def_span(m: &ir::Module, def_idx: usize) -> Span {
    m.definitions[def_idx].span()
}

fn first_component_dep_symbol(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    comp: &ir::OidComponent,
) -> Option<graph::Symbol> {
    match comp {
        ir::OidComponent::Name { name, .. } => {
            if is_well_known_root(name) {
                return None;
            }
            if let Some(symbol) = resolve_dep_symbol(ctx, ir_mod, name) {
                return Some(symbol);
            }
            lookup_smi_global_root_symbol(ctx, ir_mod, name)
        }
        ir::OidComponent::NamedNumber { name, .. } => {
            if is_well_known_root(name) {
                return None;
            }
            // NamedNumber can still resolve by numeric fallback; only add graph edge
            // when the symbolic parent is resolvable.
            if let Some(symbol) = resolve_dep_symbol(ctx, ir_mod, name) {
                return Some(symbol);
            }
            lookup_smi_global_root_symbol(ctx, ir_mod, name)
        }
        ir::OidComponent::QualifiedName { module, name, .. } => Some(graph::Symbol {
            module: module.clone(),
            name: name.clone(),
        }),
        ir::OidComponent::QualifiedNamedNumber { module, name, .. } => Some(graph::Symbol {
            module: module.clone(),
            name: name.clone(),
        }),
        ir::OidComponent::Number { .. } => None,
    }
}

fn lookup_smi_global_root_symbol(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
) -> Option<graph::Symbol> {
    if ctx.strictness.allow_constrained_fallbacks() && is_smi_global_root_symbol(ctx, name) {
        trace!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "oids",
            module = %ctx.modules[ir_mod.index()].name,
            name = %name,
            fallback = "smi_global_root_graph_edge",
            "resolved oid graph edge via constrained fallback",
        );
        return Some(graph::Symbol {
            module: "SNMPv2-SMI".to_string(),
            name: name.to_string(),
        });
    }
    None
}

fn is_smi_global_root_symbol(ctx: &ResolverContext, name: &str) -> bool {
    [ctx.snmpv2_smi, ctx.rfc1155_smi]
        .into_iter()
        .flatten()
        .any(|ir_id| {
            ctx.module_oid_def_names
                .get(&ir_id)
                .is_some_and(|defs| defs.contains(name))
        })
}

/// Resolve a dependency name to a module-qualified symbol by checking
/// the defining module's own definitions and imports.
fn resolve_dep_symbol(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
) -> Option<graph::Symbol> {
    let m = &ctx.modules[ir_mod.index()];
    // Check if defined in the same module.
    if ctx
        .module_def_names
        .get(&ir_mod)
        .is_some_and(|dn| dn.contains(name))
    {
        return Some(graph::Symbol {
            module: m.name.clone(),
            name: name.to_string(),
        });
    }
    // Check imports.
    if let Some(&source) = ctx
        .module_imports
        .get(&ir_mod)
        .and_then(|imps| imps.get(name))
    {
        return Some(graph::Symbol {
            module: ctx.modules[source.index()].name.clone(),
            name: name.to_string(),
        });
    }
    None
}

fn is_well_known_root(name: &str) -> bool {
    matches!(name, "iso" | "ccitt" | "joint-iso-ccitt")
}

fn well_known_root_arc(name: &str) -> Option<u32> {
    match name {
        "ccitt" => Some(0),
        "iso" => Some(1),
        "joint-iso-ccitt" => Some(2),
        _ => None,
    }
}

fn try_resolve_oid_definition(ctx: &mut ResolverContext, od: &OidDef) {
    let m = &ctx.modules[od.ir_mod.index()];
    let oid_assign = match get_oid_assignment(m, od.def_idx) {
        Some(oa) => oa.clone(),
        None => return,
    };
    let mut current: Option<NodeId> = None;
    let component_count = oid_assign.components.len();

    for (i, comp) in oid_assign.components.iter().enumerate() {
        let is_last = i == component_count - 1;
        let resolved = resolve_oid_component(ctx, od, current, comp, is_last);
        match resolved {
            Some(node_id) => current = Some(node_id),
            None => return,
        }
    }

    if let Some(final_node) = current {
        finalize_oid_definition(ctx, od, final_node);
    }
}

fn resolve_oid_component(
    ctx: &mut ResolverContext,
    od: &OidDef,
    current: Option<NodeId>,
    comp: &ir::OidComponent,
    is_last: bool,
) -> Option<NodeId> {
    match comp {
        ir::OidComponent::Number { value, .. } => {
            let parent = current.unwrap_or_else(|| ctx.mib.tree().root());
            Some(ctx.mib.tree.get_or_create_child(parent, *value))
        }
        ir::OidComponent::Name { name, span } => resolve_name_component(ctx, od, name, *span),
        ir::OidComponent::NamedNumber { name, number, .. } => {
            // Try name lookup first.
            if let Some(node) = lookup_name_component(ctx, od, name) {
                return Some(node);
            }
            // Fall back to creating a named child.
            let parent = current.unwrap_or_else(|| ctx.mib.tree().root());
            let child = ctx.mib.tree.get_or_create_child(parent, *number);
            ctx.module_symbol_to_node
                .entry(od.ir_mod)
                .or_default()
                .insert(name.clone(), child);
            if !is_last {
                set_intermediate_node(ctx, od, child, name);
            } else if ctx.mib.tree().get(child).name.is_empty() {
                ctx.mib.tree.set_name(child, name.clone());
            }
            Some(child)
        }
        ir::OidComponent::QualifiedName {
            module,
            name,
            span: _,
        } => {
            if let Some(node) = ctx.lookup_node_in_module(module, name) {
                Some(node)
            } else {
                let mod_name = ctx.modules[od.ir_mod.index()].name.clone();
                let comp_name = format!("{module}.{name}");
                ctx.record_unresolved_oid(
                    od.name(),
                    &comp_name,
                    &mod_name,
                    UnresolvedReason::ComponentNotFound,
                    od.ir_mod,
                    comp.span(),
                );
                None
            }
        }
        ir::OidComponent::QualifiedNamedNumber {
            module,
            name,
            number,
            ..
        } => {
            if let Some(node) = ctx.lookup_node_in_module(module, name) {
                ctx.module_symbol_to_node
                    .entry(od.ir_mod)
                    .or_default()
                    .insert(name.clone(), node);
                return Some(node);
            }
            let parent = current.unwrap_or_else(|| ctx.mib.tree().root());
            let child = ctx.mib.tree.get_or_create_child(parent, *number);
            ctx.module_symbol_to_node
                .entry(od.ir_mod)
                .or_default()
                .insert(name.clone(), child);
            if !is_last {
                set_intermediate_node(ctx, od, child, name);
            } else if ctx.mib.tree().get(child).name.is_empty() {
                ctx.mib.tree.set_name(child, name.clone());
            }
            Some(child)
        }
    }
}

/// Set name and module for an intermediate (non-leaf) OID path component,
/// gated behind should_prefer_module so that path-declaring vendor modules
/// don't overwrite ownership of well-known OIDs.
fn set_intermediate_node(ctx: &mut ResolverContext, od: &OidDef, child: NodeId, name: &str) {
    let existing_mod = ctx.mib.tree().get(child).module;
    let existing_name = ctx.mib.tree().get(child).name.clone();

    let prefer = existing_mod.is_none() || should_prefer_module(ctx, existing_mod, od.ir_mod);
    if prefer || existing_name.is_empty() {
        ctx.mib.tree.set_name(child, name.to_string());
    }
    if prefer && let Some(&resolved_mod) = ctx.module_to_resolved.get(&od.ir_mod) {
        ctx.mib.tree.set_module(child, resolved_mod);
    }
    ctx.mib.register_node(name, child);
    if ctx.mib.tree().get(child).kind == Kind::Internal {
        ctx.mib.tree.set_kind(child, Kind::Node);
    }
}

fn lookup_name_component(ctx: &mut ResolverContext, od: &OidDef, name: &str) -> Option<NodeId> {
    // Well-known roots.
    if let Some(arc) = well_known_root_arc(name) {
        let root = ctx.mib.tree().root();
        let child = ctx.mib.tree.get_or_create_child(root, arc);
        if ctx.mib.tree().get(child).name.is_empty() {
            ctx.mib.tree.set_name(child, name.to_string());
        }
        return Some(child);
    }

    // Module-scoped lookup.
    if let Some((node, used_import)) = ctx.lookup_node_for_module(od.ir_mod, name) {
        if used_import {
            ctx.mark_import_used(od.ir_mod, name);
        }
        return Some(node);
    }

    // Constrained (Normal+): SMI global OID roots.
    if ctx.strictness.allow_constrained_fallbacks()
        && let Some(node) = lookup_smi_global_oid_root(ctx, name)
    {
        trace!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "oids",
            module = %ctx.modules[od.ir_mod.index()].name,
            name = %name,
            fallback = "smi_global_root",
            "resolved oid name via constrained fallback",
        );
        return Some(node);
    }

    None
}

fn resolve_name_component(
    ctx: &mut ResolverContext,
    od: &OidDef,
    name: &str,
    span: Span,
) -> Option<NodeId> {
    if let Some(node) = lookup_name_component(ctx, od, name) {
        return Some(node);
    }

    let mod_name = ctx.modules[od.ir_mod.index()].name.clone();
    ctx.record_unresolved_oid(
        od.name(),
        name,
        &mod_name,
        UnresolvedReason::ComponentNotFound,
        od.ir_mod,
        span,
    );
    None
}

fn lookup_smi_global_oid_root(ctx: &ResolverContext, name: &str) -> Option<NodeId> {
    if let Some(smi) = ctx.snmpv2_smi
        && let Some(node) = ctx
            .module_symbol_to_node
            .get(&smi)
            .and_then(|syms| syms.get(name))
    {
        return Some(*node);
    }
    if let Some(rfc) = ctx.rfc1155_smi
        && let Some(node) = ctx
            .module_symbol_to_node
            .get(&rfc)
            .and_then(|syms| syms.get(name))
    {
        return Some(*node);
    }
    None
}

fn finalize_oid_definition(ctx: &mut ResolverContext, od: &OidDef, node_id: NodeId) {
    let (def_span, oid_definition_text, oid_definition_status) = {
        let m = &ctx.modules[od.ir_mod.index()];
        let def = &m.definitions[od.def_idx];
        let def_span = def.span();
        let (oid_definition_text, oid_definition_status) = match def {
            ir::Definition::ValueAssignment(va) => {
                (Some((va.description.clone(), va.reference.clone())), None)
            }
            ir::Definition::ObjectIdentity(oi) => (
                Some((oi.description.clone(), oi.reference.clone())),
                Some(oi.status),
            ),
            // MODULE-IDENTITY description is stored on module metadata, not on the
            // node. Populating it here would break parity with gomib, which also
            // does not set it on the node. Both repos should be updated together
            // if this changes.
            _ => (None, None),
        };
        (def_span, oid_definition_text, oid_definition_status)
    };
    let resolved_mod_id = ctx.module_to_resolved[&od.ir_mod];

    // Detect OID reuse/registration conflicts before overwriting the node label.
    let existing_name = ctx.mib.tree().get(node_id).name.clone();
    if !existing_name.is_empty() && existing_name != od.name() {
        let code = if is_registered_kind(ctx.mib.tree().get(node_id).kind) {
            crate::types::DiagCode::OidRegistered
        } else {
            crate::types::DiagCode::OidReuse
        };
        let msg = if code == crate::types::DiagCode::OidRegistered {
            format!(
                "{:?}: registers OID already registered by {:?}",
                od.name(),
                existing_name
            )
        } else {
            format!(
                "{:?}: reuses OID assigned to {:?}",
                od.name(),
                existing_name
            )
        };
        ctx.emit_diagnostic(code, Some(od.ir_mod), def_span, msg);
    }

    // RFC 2578 section 7.10: for administrative assignments the last
    // sub-identifier must not be zero (except zeroDotZero).
    if !matches!(
        od.kind,
        OidDefKind::ModuleIdentity | OidDefKind::ObjectIdentity | OidDefKind::ValueAssignment
    ) {
        let oid = ctx.mib.tree().oid_of(node_id);
        if !oid.is_empty() && oid[oid.len() - 1] == 0 && (oid.len() != 2 || oid[0] != 0) {
            ctx.emit_diagnostic(
                crate::types::DiagCode::LastSubidZero,
                Some(od.ir_mod),
                def_span,
                format!("{:?}: last sub-identifier must not be zero", od.name()),
            );
        }
    }

    // The node's kind, name, span, description, and module all reflect the
    // preferred module. Gate all of them behind the same preference check
    // so they stay in sync.
    let existing_mod = ctx.mib.tree().get(node_id).module;
    let prefer = existing_mod.is_none() || should_prefer_module(ctx, existing_mod, od.ir_mod);

    if prefer {
        ctx.mib.tree.set_name(node_id, od.name().to_string());

        let node_kind = od.kind.to_node_kind();
        ctx.mib.tree.set_kind(node_id, node_kind);

        ctx.mib.tree.set_span(node_id, def_span);

        if let Some((description, reference)) = oid_definition_text {
            if !description.is_empty() {
                ctx.mib.tree.set_description(node_id, description);
            }
            if !reference.is_empty() {
                ctx.mib.tree.set_reference(node_id, reference);
            }
        }

        if let Some(status) = oid_definition_status {
            ctx.mib.tree.set_status(node_id, status);
        }

        ctx.mib.tree.set_module(node_id, resolved_mod_id);
        if od.kind == OidDefKind::ModuleIdentity {
            let oid = ctx.mib.tree().oid_of(node_id).clone();
            ctx.mib.module_mut(resolved_mod_id).oid = Some(oid);
        }
    } else if existing_name.is_empty() {
        // No prior name - set name even if module isn't preferred, so the
        // node isn't left unnamed.
        ctx.mib.tree.set_name(node_id, od.name().to_string());
    }

    // Register symbol -> node mapping.
    ctx.module_symbol_to_node
        .entry(od.ir_mod)
        .or_default()
        .insert(od.name().to_string(), node_id);

    // Register in Mib name index.
    ctx.mib.register_node(od.name(), node_id);

    // Non-semantic definitions get added to module's node list now.
    // Semantic definitions (ObjectType, Notification, etc.) are deferred to semantics phase.
    match od.kind {
        OidDefKind::ValueAssignment | OidDefKind::ObjectIdentity | OidDefKind::ModuleIdentity => {
            ctx.mib
                .module_mut(resolved_mod_id)
                .add_node(od.name(), node_id);
        }
        _ => {} // deferred to semantics
    }
}

fn finalize_trap_type_definition(ctx: &mut ResolverContext, od: &OidDef, node_id: NodeId) {
    let resolved_mod_id = ctx.module_to_resolved[&od.ir_mod];
    let existing_mod = ctx.mib.tree().get(node_id).module;
    let prefer = existing_mod.is_none() || should_prefer_module(ctx, existing_mod, od.ir_mod);

    if prefer {
        ctx.mib.tree.set_name(node_id, od.name().to_string());
        ctx.mib.tree.set_kind(node_id, Kind::Notification);
        ctx.mib.tree.set_module(node_id, resolved_mod_id);
    } else if ctx.mib.tree().get(node_id).name.is_empty() {
        ctx.mib.tree.set_name(node_id, od.name().to_string());
    }

    ctx.module_symbol_to_node
        .entry(od.ir_mod)
        .or_default()
        .insert(od.name().to_string(), node_id);
    ctx.mib.register_node(od.name(), node_id);
}

fn is_registered_kind(kind: Kind) -> bool {
    matches!(
        kind,
        Kind::Scalar
            | Kind::Table
            | Kind::Row
            | Kind::Column
            | Kind::Notification
            | Kind::Group
            | Kind::Compliance
            | Kind::Capability
    )
}

/// Resolve TRAP-TYPE definitions (OID derived from enterprise + trap number).
fn resolve_trap_type_definitions(ctx: &mut ResolverContext, trap_defs: &[OidDef]) {
    // snmpTraps OID: 1.3.6.1.6.3.1.1.5
    let snmp_traps_oid = [1u32, 3, 6, 1, 6, 3, 1, 1, 5];

    for od in trap_defs {
        // Extract data from IR before mutable operations.
        let (enterprise_name, trap_number, span) = {
            let m = &ctx.modules[od.ir_mod.index()];
            let def = &m.definitions[od.def_idx];
            let notif = match def {
                ir::Definition::Notification(n) => n,
                _ => continue,
            };
            let trap_info = match &notif.trap_info {
                Some(ti) => ti,
                None => continue,
            };
            (
                trap_info.enterprise.clone(),
                trap_info.trap_number,
                notif.span,
            )
        };

        // Look up the enterprise node.
        let enterprise_node = if let Some((node, used_import)) =
            ctx.lookup_node_for_module(od.ir_mod, &enterprise_name)
        {
            if used_import {
                ctx.mark_import_used(od.ir_mod, &enterprise_name);
            }
            Some(node)
        } else if ctx.strictness.allow_constrained_fallbacks() {
            ctx.lookup_node_global(&enterprise_name)
        } else {
            None
        };

        let enterprise_node = match enterprise_node {
            Some(n) => n,
            None => {
                let mod_name = ctx.modules[od.ir_mod.index()].name.clone();
                ctx.record_unresolved_oid(
                    od.name(),
                    &enterprise_name,
                    &mod_name,
                    UnresolvedReason::EnterpriseNotFound,
                    od.ir_mod,
                    span,
                );
                continue;
            }
        };

        // Determine OID based on RFC 3584 rules.
        let enterprise_oid = ctx.mib.tree().oid_of(enterprise_node).clone();
        let trap_node = if enterprise_oid.len() == snmp_traps_oid.len()
            && enterprise_oid
                .iter()
                .zip(snmp_traps_oid.iter())
                .all(|(a, b)| a == b)
        {
            // Generic trap: snmpTraps.(trapNumber+1)
            let arc = trap_number + 1;
            ctx.mib.tree.get_or_create_child(enterprise_node, arc)
        } else {
            // Enterprise-specific: enterprise.0.trapNumber
            let zero = ctx.mib.tree.get_or_create_child(enterprise_node, 0);
            ctx.mib.tree.get_or_create_child(zero, trap_number)
        };

        finalize_trap_type_definition(ctx, od, trap_node);
    }
}

pub(super) fn should_prefer_module(
    ctx: &ResolverContext,
    current_resolved: Option<ModuleId>,
    new_ir: IrModuleId,
) -> bool {
    let current_resolved = match current_resolved {
        None => return true,
        Some(m) => m,
    };
    let current_ir = match ctx.resolved_to_module.get(&current_resolved) {
        None => return true,
        Some(&m) => m,
    };

    // Base modules always win. They are the authoritative source for
    // well-known OIDs (iso, org, dod, internet, etc.).
    let new_is_base = base_modules::is_base_module(&ctx.modules[new_ir.index()].name);
    let current_is_base = base_modules::is_base_module(&ctx.modules[current_ir.index()].name);
    if new_is_base != current_is_base {
        return new_is_base;
    }

    let new_rank = language_rank(ctx.module_language(new_ir));
    let current_rank = language_rank(ctx.module_language(current_ir));

    if new_rank != current_rank {
        return new_rank > current_rank;
    }

    // Same language rank - use LAST-UPDATED as tiebreaker (newer wins).
    let new_ts = normalize_timestamp(&ctx.extract_last_updated(new_ir));
    let current_ts = normalize_timestamp(&ctx.extract_last_updated(current_ir));
    if new_ts != current_ts {
        return new_ts > current_ts;
    }

    // Deterministic fallback: lexicographic module name for stable results
    // across implementations. No semantic basis, but reproducible.
    let new_name = &ctx.modules[new_ir.index()].name;
    let current_name = &ctx.modules[current_ir.index()].name;
    new_name < current_name
}
