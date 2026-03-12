use crate::ir;
use crate::mib::Oid;
use crate::types::{Access, BaseType, DiagCode, Kind, Span, Status};
use tracing::trace;

use super::super::capability::CapabilityData;
use super::super::compliance::ComplianceData;
use super::super::group::GroupData;
use super::super::notification::NotificationData;
use super::super::object::ObjectData;
use super::super::types::*;
use super::context::{IrModuleId, ResolverContext, UnresolvedReason};

/// Phase 5: Create resolved entities and run structural validation.
pub(super) fn resolve_semantics(ctx: &mut ResolverContext) {
    infer_node_kinds(ctx);
    create_resolved_objects(ctx);
    validate_table_semantics(ctx);
    link_object_indexes(ctx);
    check_augments_nesting(ctx);
    create_resolved_notifications(ctx);
    create_resolved_groups(ctx);
    create_resolved_compliances(ctx);
    create_resolved_capabilities(ctx);
}

/// Classify OBJECT-TYPE nodes into table/row/scalar/column.
fn infer_node_kinds(ctx: &mut ResolverContext) {
    for idx in 0..ctx.modules.len() {
        let m = &ctx.modules[idx];
        let ir_id = IrModuleId(idx as u32);

        for def in &m.definitions {
            let ot = match def {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };

            let node_id = match ctx
                .module_symbol_to_node
                .get(&ir_id)
                .and_then(|syms| syms.get(&ot.name))
            {
                Some(&id) => id,
                None => continue,
            };

            let kind = if matches!(ot.syntax, ir::TypeSyntax::SequenceOf { .. }) {
                Kind::Table
            } else if !ot.index.is_empty() || !ot.augments.is_empty() {
                Kind::Row
            } else {
                Kind::Scalar
            };

            ctx.mib.tree.set_kind(node_id, kind);
        }
    }

    // Reclassify children of Row nodes as columns.
    let all_nodes: Vec<NodeId> = ctx.mib.tree().all_nodes().collect();
    for node_id in &all_nodes {
        let kind = ctx.mib.tree().get(*node_id).kind;
        if kind != Kind::Row {
            continue;
        }
        let children: Vec<NodeId> = ctx
            .mib
            .tree()
            .get(*node_id)
            .children
            .values()
            .copied()
            .collect();
        for child_id in children {
            if ctx.mib.tree().get(child_id).kind == Kind::Scalar {
                ctx.mib.tree.set_kind(child_id, Kind::Column);
            }
        }
    }

    let mut table_count = 0;
    let mut row_count = 0;
    let mut column_count = 0;
    let mut scalar_count = 0;
    for node_id in ctx.mib.tree().all_nodes() {
        match ctx.mib.tree().get(node_id).kind {
            Kind::Table => table_count += 1,
            Kind::Row => row_count += 1,
            Kind::Column => column_count += 1,
            Kind::Scalar => scalar_count += 1,
            _ => {}
        }
    }

    trace!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = "semantics",
        table_count = table_count,
        row_count = row_count,
        column_count = column_count,
        scalar_count = scalar_count,
        "classified object node kinds",
    );
}

/// Create resolved Object instances from OBJECT-TYPE definitions.
fn create_resolved_objects(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::ObjectType(_)));

    let mut created_object_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];
        let ot = match &ctx.modules[mod_idx].definitions[def_idx] {
            ir::Definition::ObjectType(ot) => ot,
            _ => continue,
        };

        let node_id = match ctx
            .module_symbol_to_node
            .get(&ir_id)
            .and_then(|syms| syms.get(&ot.name))
        {
            Some(&id) => id,
            None => continue,
        };

        // Extract all data from ot before mutable operations.
        let name = ot.name.clone();
        let span = ot.span;
        let status = ot.status;
        let description = ot.description.clone();
        let reference = ot.reference.clone();
        let status_span = ot.status_span;
        let desc_span = ot.description_span;
        let ref_span = ot.reference_span;
        let access = ot.access;
        let units = ot.units.clone();
        let syntax_span = ot.syntax_span;
        let access_span = ot.access_span;
        let units_span = ot.units_span;
        let augments_span = ot.augments_span;
        let defval_span = ot.defval_span;
        let syntax = ot.syntax.clone();
        let defval = ot.defval.clone();
        let oid = ot.oid.clone();

        let mut obj = ObjectData::new(name.clone());
        obj.entity.span = span;
        obj.entity.node = Some(node_id);
        obj.entity.module = Some(resolved_mod);
        obj.entity.status = status;
        obj.entity.description = description;
        obj.entity.reference = reference;
        obj.entity.status_span = status_span;
        obj.entity.desc_span = desc_span;
        obj.entity.ref_span = ref_span;
        obj.access = access;
        obj.units = units;
        obj.syntax_span = syntax_span;
        obj.access_span = access_span;
        obj.units_span = units_span;
        obj.augments_span = augments_span;
        obj.def_val_span = defval_span;

        // Resolve type reference.
        let obj_name = obj.entity.name.clone();
        let resolved = resolve_type_syntax(ctx, ir_id, &syntax, &obj_name, obj.syntax_span);
        obj.typ = resolved.type_id;
        obj.enums = resolved.enums;
        obj.bits = resolved.bits;
        obj.sizes = resolved.sizes;
        obj.ranges = resolved.ranges;

        // Convert DEFVAL.
        if let Some(dv) = &defval {
            obj.def_val = Some(convert_defval(ctx, ir_id, dv, obj.typ, obj.def_val_span));
        }

        // Compute effective values from type chain.
        compute_effective_values(ctx, &mut obj);

        // Build OID refs from the OID assignment.
        obj.entity.oid_refs = build_oid_refs(&oid);

        // Store sequence type name for rows.
        if let ir::TypeSyntax::SequenceOf { entry_type, .. } = &syntax {
            obj.sequence_type_name = entry_type.clone();
        }

        let obj_id = ctx.mib.add_object(obj);

        // Attach to node - prefer SMIv2 modules when multiple modules
        // define the same OID (e.g., TCP-MIB and RFC1213-MIB both define
        // tcpConnTable). Compare the existing object's source module, not
        // the node's module from OID phase.
        let existing_obj = ctx.mib.tree().get(node_id).object;
        let existing_obj_mod = existing_obj.and_then(|oid| ctx.mib.object(oid).module());
        if existing_obj.is_none() || super::oids::should_prefer_module(ctx, existing_obj_mod, ir_id)
        {
            ctx.mib.tree.attach_object(node_id, obj_id);
        }

        // Register in module.
        ctx.mib.module_mut(resolved_mod).add_object(&name, obj_id);
        ctx.mib.module_mut(resolved_mod).add_node(&name, node_id);
        created_object_count += 1;
    }

    trace!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = "semantics",
        object_count = created_object_count,
        "created resolved objects",
    );
}

/// Resolve type syntax into a SyntaxConstraints, handling type lookups,
/// named numbers, bits, and constraints.
///
/// Used by both OBJECT-TYPE resolution and SYNTAX/WRITE-SYNTAX clauses in
/// MODULE-COMPLIANCE and AGENT-CAPABILITIES.
fn resolve_type_syntax(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    syntax: &ir::TypeSyntax,
    referrer: &str,
    span: Span,
) -> SyntaxConstraints {
    let mut sc = SyntaxConstraints {
        type_id: None,
        sizes: Vec::new(),
        ranges: Vec::new(),
        enums: Vec::new(),
        bits: Vec::new(),
    };
    resolve_type_syntax_into(ctx, ir_mod, syntax, referrer, span, &mut sc);
    sc
}

fn resolve_type_syntax_into(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    syntax: &ir::TypeSyntax,
    referrer: &str,
    span: Span,
    sc: &mut SyntaxConstraints,
) {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => {
            if let Some((type_id, used_import)) = ctx.lookup_type_for_module(ir_mod, name) {
                sc.type_id = Some(type_id);
                if used_import {
                    ctx.mark_import_used(ir_mod, name);
                }
            } else if !is_sequence_type_def(ctx, ir_mod, name) {
                let mod_name = ctx.modules[ir_mod.index()].name.clone();
                ctx.record_unresolved_type(referrer, name, &mod_name, ir_mod, span);
            }
        }
        ir::TypeSyntax::IntegerEnum {
            base,
            named_numbers,
            ..
        } => {
            if !base.is_empty() {
                if let Some((type_id, used_import)) = ctx.lookup_type_for_module(ir_mod, base) {
                    sc.type_id = Some(type_id);
                    if used_import {
                        ctx.mark_import_used(ir_mod, base);
                    }
                } else {
                    let mod_name = ctx.modules[ir_mod.index()].name.clone();
                    ctx.record_unresolved_type(referrer, base, &mod_name, ir_mod, span);
                }
            } else if let Some((type_id, _)) = ctx.lookup_type_for_module(ir_mod, "INTEGER") {
                sc.type_id = Some(type_id);
            }
            sc.enums = named_numbers
                .iter()
                .map(|nn| NamedValue {
                    label: nn.name.clone(),
                    value: nn.value,
                    span: nn.span,
                })
                .collect();
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            if let Some((type_id, _)) = ctx.lookup_type_for_module(ir_mod, "BITS") {
                sc.type_id = Some(type_id);
            }
            sc.bits = named_bits
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
            resolve_type_syntax_into(ctx, ir_mod, base, referrer, span, sc);
            match constraint {
                ir::Constraint::Size { ranges, .. } => {
                    sc.sizes = ranges
                        .iter()
                        .filter_map(super::types::resolve_range)
                        .collect();
                }
                ir::Constraint::Range { ranges, .. } => {
                    sc.ranges = ranges
                        .iter()
                        .filter_map(super::types::resolve_range)
                        .collect();
                }
            }
        }
        ir::TypeSyntax::SequenceOf { .. } | ir::TypeSyntax::Sequence { .. } => {}
        ir::TypeSyntax::OctetString => {
            if let Some((type_id, _)) = ctx.lookup_type_for_module(ir_mod, "OCTET STRING") {
                sc.type_id = Some(type_id);
            }
        }
        ir::TypeSyntax::ObjectIdentifier => {
            if let Some((type_id, _)) = ctx.lookup_type_for_module(ir_mod, "OBJECT IDENTIFIER") {
                sc.type_id = Some(type_id);
            }
        }
    }
}

/// Compute effective values by walking the type chain.
fn compute_effective_values(ctx: &ResolverContext, obj: &mut ObjectData) {
    let type_id = match obj.typ {
        Some(id) => id,
        None => return,
    };

    let types = ctx.mib.types_slice();
    let t = &types[type_id.index() as usize];

    // Display hint: object-level is empty, so walk type chain.
    if obj.hint.is_empty() {
        obj.hint = t.effective_display_hint(types).to_string();
    }

    // Sizes, ranges, enums, bits: object-level takes precedence.
    if obj.sizes.is_empty() {
        obj.sizes = t.effective_sizes(types).to_vec();
    }
    if obj.ranges.is_empty() {
        obj.ranges = t.effective_ranges(types).to_vec();
    }
    if obj.enums.is_empty() {
        obj.enums = t.effective_enums(types).to_vec();
    }
    if obj.bits.is_empty() {
        obj.bits = t.effective_bits(types).to_vec();
    }
}

/// Validate INDEX and AUGMENTS references at the IR level for all ObjectType
/// definitions. This mirrors gomib's resolveTableSemantics: it emits diagnostics
/// for unresolvable INDEX/AUGMENTS targets regardless of whether the object's
/// own OID resolved (and thus whether a resolved object was created).
fn validate_table_semantics(ctx: &mut ResolverContext) {
    for mod_idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(mod_idx as u32);

        let work: Vec<(String, Vec<ir::definition::IndexItem>, String, Span)> = ctx.modules
            [mod_idx]
            .definitions
            .iter()
            .filter_map(|def| match def {
                ir::Definition::ObjectType(ot)
                    if !ot.index.is_empty() || !ot.augments.is_empty() =>
                {
                    Some((
                        ot.name.clone(),
                        ot.index.clone(),
                        ot.augments.clone(),
                        ot.augments_span,
                    ))
                }
                _ => None,
            })
            .collect();

        for (name, index_items, augments, augments_span) in work {
            if !index_items.is_empty() {
                for item in &index_items {
                    if is_bare_type_index(&item.object) {
                        continue;
                    }
                    if ctx.lookup_node_for_module(ir_id, &item.object).is_none() {
                        let mod_name = ctx.modules[mod_idx].name.clone();
                        ctx.record_unresolved_index(
                            &name,
                            &item.object,
                            &mod_name,
                            ir_id,
                            item.span,
                        );
                    }
                }
            }

            if !augments.is_empty() && ctx.lookup_node_for_module(ir_id, &augments).is_none() {
                let mod_name = ctx.modules[mod_idx].name.clone();
                ctx.record_unresolved_oid(
                    &name,
                    &augments,
                    &mod_name,
                    UnresolvedReason::AugmentsTargetNotFound,
                    ir_id,
                    augments_span,
                );
            }
        }
    }
}

/// Resolve INDEX and AUGMENTS references after all objects exist.
fn link_object_indexes(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::ObjectType(_)));

    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);

        // Extract needed data before mutable operations.
        let (name, index_items, augments) = {
            let ot = match &ctx.modules[mod_idx].definitions[def_idx] {
                ir::Definition::ObjectType(ot) => ot,
                _ => continue,
            };
            (ot.name.clone(), ot.index.clone(), ot.augments.clone())
        };

        let obj_id = match ctx.lookup_object_for_module(ir_id, &name) {
            Some((id, used_import)) => {
                if used_import {
                    ctx.mark_import_used(ir_id, &name);
                }
                id
            }
            None => continue,
        };

        // Resolve INDEX entries.
        if !index_items.is_empty() {
            let mut entries = Vec::new();
            for item in &index_items {
                if let Some(entry) = resolve_index_entry(ctx, ir_id, &name, item) {
                    entries.push(entry);
                }
            }
            ctx.mib.object_mut(obj_id).index = entries;
        }

        // Resolve AUGMENTS. Diagnostic for unresolved targets is emitted
        // by validate_table_semantics.
        if !augments.is_empty()
            && let Some(target_obj_id) = lookup_object_in_module_scope(ctx, ir_id, &augments)
        {
            ctx.mib.object_mut(obj_id).augments = Some(target_obj_id);
            ctx.mib.object_mut(target_obj_id).augmented_by.push(obj_id);
        }
    }
}

fn check_augments_nesting(ctx: &mut ResolverContext) {
    for mod_idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(mod_idx as u32);
        let work: Vec<(String, String, Span)> = ctx.modules[mod_idx]
            .definitions
            .iter()
            .filter_map(|def| match def {
                ir::Definition::ObjectType(ot) if !ot.augments.is_empty() => {
                    Some((ot.name.clone(), ot.augments.clone(), ot.span))
                }
                _ => None,
            })
            .collect();

        for (name, augments, span) in work {
            let Some(obj_id) = lookup_object_in_module_scope(ctx, ir_id, &name) else {
                continue;
            };
            let Some(target_obj_id) = ctx.mib.object(obj_id).augments() else {
                continue;
            };
            if ctx.mib.object(target_obj_id).augments().is_some() {
                ctx.emit_diagnostic(
                    DiagCode::AugmentNested,
                    Some(ir_id),
                    span,
                    format!(
                        "{:?} augments {:?} which is not a base table row",
                        name, augments
                    ),
                );
            }
        }
    }
}

fn resolve_index_entry(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    _row_name: &str,
    item: &ir::definition::IndexItem,
) -> Option<IndexEntry> {
    if is_bare_type_index(&item.object) {
        return Some(IndexEntry {
            object: None,
            type_name: item.object.clone(),
            implied: item.implied,
            encoding: crate::types::IndexEncoding::Unknown,
            span: item.span,
        });
    }

    // Diagnostic for unresolved INDEX is emitted by validate_table_semantics.
    let obj = lookup_object_in_module_scope(ctx, ir_mod, &item.object);

    let encoding = if let Some(obj_id) = obj {
        let o = ctx.mib.object(obj_id);
        let base = o.typ.map_or(BaseType::Unknown, |tid| {
            ctx.mib.type_(tid).effective_base(ctx.mib.types_slice())
        });
        let sizes = if !o.sizes.is_empty() {
            &o.sizes
        } else if let Some(tid) = o.typ {
            ctx.mib.type_(tid).effective_sizes(ctx.mib.types_slice())
        } else {
            &[]
        };
        classify_index_encoding(base, item.implied, sizes)
    } else {
        return None;
    };

    Some(IndexEntry {
        object: obj,
        type_name: item.object.clone(),
        implied: item.implied,
        encoding,
        span: item.span,
    })
}

// Primitive/global type names that can appear directly in INDEX clauses.
fn is_bare_type_index(name: &str) -> bool {
    matches!(
        name,
        "INTEGER"
            | "OCTET STRING"
            | "BITS"
            | "Integer32"
            | "Counter32"
            | "Counter64"
            | "Gauge32"
            | "Unsigned32"
            | "TimeTicks"
            | "IpAddress"
            | "Opaque"
            | "Counter"
            | "Gauge"
            | "NetworkAddress"
    )
}

fn lookup_object_by_name(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
) -> Option<ObjectId> {
    if let Some(obj_id) = lookup_object_in_module_scope(ctx, ir_mod, name) {
        return Some(obj_id);
    }
    if ctx.strictness.allow_global_fallbacks()
        && let Some(node_id) = ctx.lookup_node_global(name)
    {
        trace!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "semantics",
            module = %ctx.modules[ir_mod.index()].name,
            name = %name,
            fallback = "global_object_lookup",
            "resolved object via global fallback",
        );
        return ctx.mib.tree().get(node_id).object;
    }
    None
}

fn lookup_object_in_module_scope(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
) -> Option<ObjectId> {
    if let Some((obj_id, used_import)) = ctx.lookup_object_for_module(ir_mod, name) {
        if used_import {
            ctx.mark_import_used(ir_mod, name);
        }
        return Some(obj_id);
    }
    None
}

/// Create resolved Notification instances.
fn create_resolved_notifications(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::Notification(_)));

    let mut created_notification_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        // Extract data before mutable operations.
        let (name, span, objects, status, description, reference, trap_info, oid) = {
            let notif = match &ctx.modules[mod_idx].definitions[def_idx] {
                ir::Definition::Notification(n) => n,
                _ => continue,
            };
            (
                notif.name.clone(),
                notif.span,
                notif.objects.clone(),
                notif.status,
                notif.description.clone(),
                notif.reference.clone(),
                notif.trap_info.clone(),
                notif.oid.clone(),
            )
        };

        let node_id = match ctx
            .module_symbol_to_node
            .get(&ir_id)
            .and_then(|syms| syms.get(&name))
        {
            Some(&id) => id,
            None => continue,
        };

        let mut nd = NotificationData::new(name.clone());
        nd.entity.span = span;
        nd.entity.node = Some(node_id);
        nd.entity.module = Some(resolved_mod);
        nd.entity.status = status;
        nd.entity.description = description;
        nd.entity.reference = reference;

        // Resolve OBJECTS list.
        for obj_name in &objects {
            let obj = lookup_object_by_name(ctx, ir_id, obj_name);
            if let Some(obj_id) = obj {
                if ctx.mib.object(obj_id).access() == Access::NotAccessible {
                    ctx.emit_diagnostic(
                        DiagCode::NotifObjectAccess,
                        Some(ir_id),
                        span,
                        format!(
                            "notification {:?} references {:?} which is not-accessible",
                            name, obj_name
                        ),
                    );
                }
                nd.objects.push(obj_id);
            } else {
                let mod_name = ctx.modules[mod_idx].name.clone();
                ctx.record_unresolved_notification_object(&name, obj_name, &mod_name, ir_id, span);
            }
        }

        // Set TrapInfo.
        if let Some(ti) = &trap_info {
            nd.trap_info = Some(TrapInfo {
                enterprise: ti.enterprise.clone(),
                trap_number: ti.trap_number,
            });
        }

        // Build OID refs.
        if let Some(oid) = &oid {
            nd.entity.oid_refs = build_oid_refs(oid);
        }

        let notif_id = ctx.mib.add_notification(nd);

        let existing = ctx.mib.tree().get(node_id).notification;
        let existing_mod = existing.and_then(|id| ctx.mib.notification(id).module());
        if existing.is_none() || super::oids::should_prefer_module(ctx, existing_mod, ir_id) {
            ctx.mib.tree.attach_notification(node_id, notif_id);
        }

        ctx.mib
            .module_mut(resolved_mod)
            .add_notification(&name, notif_id);
        ctx.mib.module_mut(resolved_mod).add_node(&name, node_id);
        created_notification_count += 1;
    }

    trace!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = "semantics",
        notification_count = created_notification_count,
        "created resolved notifications",
    );
}

/// Create resolved Group instances (both OBJECT-GROUP and NOTIFICATION-GROUP).
fn create_resolved_groups(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| {
        matches!(
            def,
            ir::Definition::ObjectGroup(_) | ir::Definition::NotificationGroup(_)
        )
    });

    let mut created_group_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        let (name, span, members, status, description, reference, oid, is_notif) = {
            let def = &ctx.modules[mod_idx].definitions[def_idx];
            match def {
                ir::Definition::ObjectGroup(g) => (
                    g.name.clone(),
                    g.span,
                    g.objects.clone(),
                    g.status,
                    g.description.clone(),
                    g.reference.clone(),
                    g.oid.clone(),
                    false,
                ),
                ir::Definition::NotificationGroup(g) => (
                    g.name.clone(),
                    g.span,
                    g.notifications.clone(),
                    g.status,
                    g.description.clone(),
                    g.reference.clone(),
                    g.oid.clone(),
                    true,
                ),
                _ => continue,
            }
        };

        let node_id = match ctx
            .module_symbol_to_node
            .get(&ir_id)
            .and_then(|syms| syms.get(name.as_str()))
        {
            Some(&id) => id,
            None => continue,
        };

        let mut gd = GroupData::new(name.clone());
        gd.entity.span = span;
        gd.entity.node = Some(node_id);
        gd.entity.module = Some(resolved_mod);
        gd.entity.status = status;
        gd.entity.description = description;
        gd.entity.reference = reference;
        gd.is_notification_group = is_notif;
        gd.entity.oid_refs = build_oid_refs(&oid);

        let mut has_objects = false;
        let mut has_notifications = false;

        // Resolve members.
        for member_name in &members {
            if let Some((member_node, used_import)) = lookup_member_node(ctx, ir_id, member_name) {
                if used_import {
                    ctx.mark_import_used(ir_id, member_name);
                }

                let (kind, object_id) = {
                    let node = ctx.mib.tree().get(member_node);
                    (node.kind, node.object)
                };

                if is_notif {
                    if kind.is_object_type() {
                        has_objects = true;
                        ctx.emit_diagnostic(
                            DiagCode::GroupNotificationsObject,
                            Some(ir_id),
                            span,
                            format!(
                                "notification group {:?} includes object {:?}",
                                name, member_name
                            ),
                        );
                    } else if kind == Kind::Notification {
                        has_notifications = true;
                    }
                } else {
                    if kind == Kind::Notification {
                        has_notifications = true;
                        ctx.emit_diagnostic(
                            DiagCode::GroupObjectsNotification,
                            Some(ir_id),
                            span,
                            format!(
                                "object group {:?} includes notification {:?}",
                                name, member_name
                            ),
                        );
                    } else if kind.is_object_type() {
                        has_objects = true;
                    }

                    if let Some(obj_id) = object_id
                        && ctx.mib.object(obj_id).access() == Access::NotAccessible
                    {
                        ctx.emit_diagnostic(
                            DiagCode::GroupNotAccessible,
                            Some(ir_id),
                            span,
                            format!(
                                "object {:?} of group {:?} must not be not-accessible",
                                member_name, name
                            ),
                        );
                    }
                }

                check_group_member_status(
                    ctx,
                    ir_id,
                    span,
                    status,
                    &name,
                    member_node,
                    member_name,
                );
                gd.members.push(member_node);
            } else {
                ctx.emit_diagnostic(
                    DiagCode::GroupMemberUnresolved,
                    Some(ir_id),
                    span,
                    format!(
                        "group {:?} references unresolved member {:?}",
                        name, member_name
                    ),
                );
            }
        }

        if has_objects && has_notifications {
            ctx.emit_diagnostic(
                DiagCode::GroupMemberMixed,
                Some(ir_id),
                span,
                format!(
                    "group {:?} contains scalars/columns and notifications",
                    name
                ),
            );
        }

        let group_id = ctx.mib.add_group(gd);

        let existing = ctx.mib.tree().get(node_id).group;
        let existing_mod = existing.and_then(|id| ctx.mib.group(id).module());
        if existing.is_none() || super::oids::should_prefer_module(ctx, existing_mod, ir_id) {
            ctx.mib.tree.attach_group(node_id, group_id);
        }

        ctx.mib.module_mut(resolved_mod).add_group(&name, group_id);
        ctx.mib.module_mut(resolved_mod).add_node(&name, node_id);
        created_group_count += 1;
    }

    trace!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = "semantics",
        group_count = created_group_count,
        "created resolved groups",
    );
}

fn member_node_status(ctx: &ResolverContext, node_id: NodeId) -> Option<Status> {
    let node = ctx.mib.tree().get(node_id);
    if let Some(obj_id) = node.object {
        return Some(ctx.mib.object(obj_id).status());
    }
    if let Some(notif_id) = node.notification {
        return Some(ctx.mib.notification(notif_id).status());
    }
    None
}

fn status_ord(status: Status) -> u8 {
    match status {
        Status::Current => 0,
        Status::Deprecated => 1,
        Status::Obsolete => 2,
        _ => 0,
    }
}

fn check_group_member_status(
    ctx: &mut ResolverContext,
    ir_id: IrModuleId,
    span: Span,
    group_status: Status,
    group_name: &str,
    member_node: NodeId,
    member_name: &str,
) {
    let Some(member_status) = member_node_status(ctx, member_node) else {
        return;
    };
    if member_status.is_smiv1() || group_status.is_smiv1() {
        return;
    }
    if status_ord(member_status) > status_ord(group_status) {
        ctx.emit_diagnostic(
            DiagCode::GroupObjectStatus,
            Some(ir_id),
            span,
            format!(
                "{} group {:?} includes {} member {:?}",
                group_status, group_name, member_status, member_name
            ),
        );
    }
}

/// Create resolved Compliance instances.
fn create_resolved_compliances(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::ModuleCompliance(_)));

    let mut created_compliance_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        // Pre-extract compliance module data in a scoped borrow so later
        // resolution work can mutate ctx without borrow-ending placeholders.
        struct CompObjData {
            object: String,
            syntax: Option<ir::TypeSyntax>,
            write_syntax: Option<ir::TypeSyntax>,
            min_access: Option<Access>,
            description: String,
            span: Span,
        }
        struct CompModData {
            module_name: String,
            mandatory_groups: Vec<String>,
            groups: Vec<ComplianceGroup>,
            objects: Vec<CompObjData>,
            span: Span,
        }

        let (name, span, status, description, reference, oid, ir_mod_name, comp_mod_data): (
            String,
            Span,
            crate::types::Status,
            String,
            String,
            crate::ir::OidAssignment,
            String,
            Vec<CompModData>,
        ) = {
            let mc = match &ctx.modules[mod_idx].definitions[def_idx] {
                ir::Definition::ModuleCompliance(mc) => mc,
                _ => continue,
            };

            (
                mc.name.clone(),
                mc.span,
                mc.status,
                mc.description.clone(),
                mc.reference.clone(),
                mc.oid.clone(),
                ctx.modules[mod_idx].name.clone(),
                mc.modules
                    .iter()
                    .map(|cm| {
                        let module_name = if cm.module_name.is_empty() {
                            ctx.modules[mod_idx].name.clone()
                        } else {
                            cm.module_name.clone()
                        };
                        let groups = cm
                            .groups
                            .iter()
                            .map(|g| ComplianceGroup {
                                group: g.group.clone(),
                                description: g.description.clone(),
                                span: g.span,
                            })
                            .collect();
                        let objects = cm
                            .objects
                            .iter()
                            .map(|o| CompObjData {
                                object: o.object.clone(),
                                syntax: o.syntax.clone(),
                                write_syntax: o.write_syntax.clone(),
                                min_access: o.min_access,
                                description: o.description.clone(),
                                span: o.span,
                            })
                            .collect();
                        CompModData {
                            module_name,
                            mandatory_groups: cm.mandatory_groups.clone(),
                            groups,
                            objects,
                            span: cm.span,
                        }
                    })
                    .collect(),
            )
        };

        let mut comp_modules = Vec::new();
        for cmd in &comp_mod_data {
            if cmd.module_name == ir_mod_name {
                for group_name in &cmd.mandatory_groups {
                    if let Some((_, used_import)) = ctx.lookup_node_for_module(ir_id, group_name)
                        && used_import
                    {
                        ctx.mark_import_used(ir_id, group_name);
                    }
                }
                for group in &cmd.groups {
                    if let Some((_, used_import)) = ctx.lookup_node_for_module(ir_id, &group.group)
                        && used_import
                    {
                        ctx.mark_import_used(ir_id, &group.group);
                    }
                }
                for object in &cmd.objects {
                    if let Some((_, used_import)) =
                        ctx.lookup_object_for_module(ir_id, &object.object)
                        && used_import
                    {
                        ctx.mark_import_used(ir_id, &object.object);
                    }
                }
            }

            let objects: Vec<ComplianceObject> = cmd
                .objects
                .iter()
                .map(|o| {
                    let resolved_syntax = o
                        .syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &o.object, o.span));
                    let resolved_write_syntax = o
                        .write_syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &o.object, o.span));
                    ComplianceObject {
                        object: o.object.clone(),
                        syntax: resolved_syntax,
                        write_syntax: resolved_write_syntax,
                        min_access: o.min_access,
                        description: o.description.clone(),
                        span: o.span,
                    }
                })
                .collect();

            comp_modules.push(ComplianceModule {
                module_name: cmd.module_name.clone(),
                mandatory_groups: cmd.mandatory_groups.clone(),
                groups: cmd.groups.clone(),
                objects,
                span: cmd.span,
            });
        }

        let node_id = match ctx
            .module_symbol_to_node
            .get(&ir_id)
            .and_then(|syms| syms.get(&name))
        {
            Some(&id) => id,
            None => continue,
        };

        let mut cd = ComplianceData::new(name.clone());
        cd.entity.span = span;
        cd.entity.node = Some(node_id);
        cd.entity.module = Some(resolved_mod);
        cd.entity.status = status;
        cd.entity.description = description;
        cd.entity.reference = reference;
        cd.entity.oid_refs = build_oid_refs(&oid);
        cd.modules = comp_modules;

        let comp_id = ctx.mib.add_compliance(cd);

        let existing = ctx.mib.tree().get(node_id).compliance;
        let existing_mod = existing.and_then(|id| ctx.mib.compliance(id).module());
        if existing.is_none() || super::oids::should_prefer_module(ctx, existing_mod, ir_id) {
            ctx.mib.tree.attach_compliance(node_id, comp_id);
        }

        ctx.mib
            .module_mut(resolved_mod)
            .add_compliance(&name, comp_id);
        ctx.mib.module_mut(resolved_mod).add_node(&name, node_id);
        created_compliance_count += 1;
    }

    trace!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = "semantics",
        compliance_count = created_compliance_count,
        "created resolved compliances",
    );
}

struct VariationData {
    name: String,
    syntax: Option<ir::TypeSyntax>,
    write_syntax: Option<ir::TypeSyntax>,
    access: Option<Access>,
    description: String,
    span: Span,
    creation_requires: Vec<String>,
    defval: Option<ir::syntax::DefVal>,
}

/// Create resolved Capability instances.
fn create_resolved_capabilities(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::AgentCapabilities(_)));

    let mut created_capability_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        // Pre-extract capability support data in a scoped borrow so later
        // resolution work can mutate ctx without borrow-ending placeholders.
        struct SupportsData {
            module_name: String,
            includes: Vec<String>,
            variations: Vec<VariationData>,
            span: Span,
        }

        let (name, span, status, description, reference, product_release, oid, supports_data): (
            String,
            Span,
            crate::types::Status,
            String,
            String,
            String,
            crate::ir::OidAssignment,
            Vec<SupportsData>,
        ) = {
            let ac = match &ctx.modules[mod_idx].definitions[def_idx] {
                ir::Definition::AgentCapabilities(ac) => ac,
                _ => continue,
            };

            (
                ac.name.clone(),
                ac.span,
                ac.status,
                ac.description.clone(),
                ac.reference.clone(),
                ac.product_release.clone(),
                ac.oid.clone(),
                ac.supports
                    .iter()
                    .map(|sm| SupportsData {
                        module_name: sm.module_name.clone(),
                        includes: sm.includes.clone(),
                        variations: sm
                            .variations
                            .iter()
                            .map(|v| VariationData {
                                name: v.name.clone(),
                                syntax: v.syntax.clone(),
                                write_syntax: v.write_syntax.clone(),
                                access: v.access,
                                description: v.description.clone(),
                                span: v.span,
                                creation_requires: v.creation_requires.clone(),
                                defval: v.defval.clone(),
                            })
                            .collect(),
                        span: sm.span,
                    })
                    .collect(),
            )
        };

        let node_id = match ctx
            .module_symbol_to_node
            .get(&ir_id)
            .and_then(|syms| syms.get(&name))
        {
            Some(&id) => id,
            None => continue,
        };

        let mut cap = CapabilityData::new(name.clone());
        cap.entity.span = span;
        cap.entity.node = Some(node_id);
        cap.entity.module = Some(resolved_mod);
        cap.entity.status = status;
        cap.entity.description = description;
        cap.entity.reference = reference;
        cap.product_release = product_release;
        cap.entity.oid_refs = build_oid_refs(&oid);

        for sd in &supports_data {
            let mut obj_vars = Vec::new();
            let mut notif_vars = Vec::new();

            for var in &sd.variations {
                let is_notif = is_notification_variation(ctx, ir_id, &sd.module_name, var);

                if is_notif {
                    if let Some(access) = var.access
                        && access != Access::NotImplemented
                    {
                        ctx.emit_diagnostic(
                            crate::types::DiagCode::VariationAccessNotifOnly,
                            Some(ir_id),
                            var.span,
                            format!(
                                "notification variation {:?} ACCESS should be not-implemented per RFC 2580",
                                var.name
                            ),
                        );
                    }
                    notif_vars.push(NotificationVariation {
                        notification: var.name.clone(),
                        access: var.access,
                        description: var.description.clone(),
                        span: var.span,
                    });
                } else {
                    let syntax = var
                        .syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &var.name, var.span));
                    let write_syntax = var
                        .write_syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &var.name, var.span));
                    // For defval, derive the type from the resolved syntax if
                    // present, otherwise fall back to None.
                    let defval_typ = syntax.as_ref().and_then(|sc| sc.type_id);
                    let def_val = var
                        .defval
                        .as_ref()
                        .map(|dv| convert_defval(ctx, ir_id, dv, defval_typ, var.span));
                    obj_vars.push(ObjectVariation {
                        object: var.name.clone(),
                        syntax,
                        write_syntax,
                        access: var.access,
                        creation_requires: var.creation_requires.clone(),
                        def_val,
                        description: var.description.clone(),
                        span: var.span,
                    });
                }
            }

            cap.supports.push(CapabilitiesModule {
                module_name: sd.module_name.clone(),
                includes: sd.includes.clone(),
                object_variations: obj_vars,
                notification_variations: notif_vars,
                span: sd.span,
            });
        }

        let cap_id = ctx.mib.add_capability(cap);

        let existing = ctx.mib.tree().get(node_id).capability;
        let existing_mod = existing.and_then(|id| ctx.mib.capability(id).module());
        if existing.is_none() || super::oids::should_prefer_module(ctx, existing_mod, ir_id) {
            ctx.mib.tree.attach_capability(node_id, cap_id);
        }

        ctx.mib
            .module_mut(resolved_mod)
            .add_capability(&name, cap_id);
        ctx.mib.module_mut(resolved_mod).add_node(&name, node_id);
        created_capability_count += 1;
    }

    trace!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = "semantics",
        capability_count = created_capability_count,
        "created resolved capabilities",
    );
}

/// Convert an IR DEFVAL to a resolved DefVal.
fn convert_defval(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    dv: &ir::syntax::DefVal,
    typ: Option<TypeId>,
    defval_span: Span,
) -> DefVal {
    match dv {
        ir::syntax::DefVal::Integer(v) => DefVal::int(*v, v.to_string()),
        ir::syntax::DefVal::Unsigned(v) => DefVal::uint(*v, v.to_string()),
        ir::syntax::DefVal::String(s) => DefVal::string(s.clone(), format!("\"{s}\"")),
        ir::syntax::DefVal::HexString(s) => {
            let raw = format!("'{s}'H");
            if s.chars()
                .any(|c| !c.is_ascii_hexdigit() && !c.is_ascii_whitespace())
            {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::MalformedHexDefval,
                    Some(ir_mod),
                    defval_span,
                    format!("malformed hex DEFVAL {raw:?}"),
                );
                return DefVal::unset();
            }
            let bytes = hex_decode(s);
            DefVal::bytes(bytes, raw)
        }
        ir::syntax::DefVal::BinaryString(s) => {
            let raw = format!("'{s}'B");
            if s.chars()
                .any(|c| c != '0' && c != '1' && !c.is_ascii_whitespace())
            {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::MalformedBinDefval,
                    Some(ir_mod),
                    defval_span,
                    format!("binary DEFVAL contains non-binary digits: {raw:?}"),
                );
            }
            let is_bits = typ.is_some_and(|tid| {
                let base = ctx.mib.type_(tid).effective_base(ctx.mib.types_slice());
                base == BaseType::Bits
            });
            let bytes = binary_decode(s, is_bits);
            DefVal::bytes(bytes, raw)
        }
        ir::syntax::DefVal::Enum(label) => {
            // Check if this is an OID reference by checking the object's base type.
            let is_oid = typ.is_some_and(|tid| {
                let base = ctx.mib.type_(tid).effective_base(ctx.mib.types_slice());
                base == BaseType::ObjectIdentifier
            });
            if is_oid {
                // Try to look up as an OID reference.
                if let Some((node_id, used_import)) = ctx.lookup_node_for_module(ir_mod, label) {
                    if used_import {
                        ctx.mark_import_used(ir_mod, label);
                    }
                    let oid = ctx.mib.tree().oid_of(node_id).clone();
                    return DefVal::oid(oid, label.clone());
                }
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    defval_span,
                    format!("DEFVAL OID reference {:?} could not be resolved", label),
                );
            }
            DefVal::enumeration(label.clone(), label.clone())
        }
        ir::syntax::DefVal::Bits { labels } => {
            let raw = if labels.is_empty() {
                "{ }".to_string()
            } else {
                format!("{{ {} }}", labels.join(", "))
            };
            DefVal::bits(labels.clone(), raw)
        }
        ir::syntax::DefVal::OidRef(name) => {
            if let Some((node_id, used_import)) = ctx.lookup_node_for_module(ir_mod, name) {
                if used_import {
                    ctx.mark_import_used(ir_mod, name);
                }
                let oid = ctx.mib.tree().oid_of(node_id).clone();
                DefVal::oid(oid, name.clone())
            } else {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    defval_span,
                    format!("DEFVAL OID reference {:?} could not be resolved", name),
                );
                DefVal::unset()
            }
        }
        ir::syntax::DefVal::OidValue { components } => {
            // Try to resolve the OID from components.
            let raw = format_oid_components(components);
            if let Some(oid) = resolve_defval_oid(ctx, ir_mod, components, defval_span) {
                DefVal::oid(oid, raw)
            } else {
                DefVal::unset()
            }
        }
        ir::syntax::DefVal::Unparsed => DefVal::unset(),
    }
}

fn resolve_defval_oid(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    components: &[ir::OidComponent],
    defval_span: Span,
) -> Option<Oid> {
    if components.is_empty() {
        ctx.emit_diagnostic(
            crate::types::DiagCode::DefvalUnresolved,
            Some(ir_mod),
            defval_span,
            "DEFVAL OID value has no components".to_string(),
        );
        return None;
    }

    let (mut arcs, start_idx) = match &components[0] {
        ir::OidComponent::Name { name, .. } | ir::OidComponent::NamedNumber { name, .. } => {
            if let Some((node_id, _)) = ctx.lookup_node_for_module(ir_mod, name) {
                (ctx.mib.tree().oid_of(node_id).to_vec(), 1)
            } else {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    defval_span,
                    format!("DEFVAL OID root {:?} could not be resolved", name),
                );
                return None;
            }
        }
        ir::OidComponent::QualifiedName { module, name, .. }
        | ir::OidComponent::QualifiedNamedNumber { module, name, .. } => {
            if let Some(node_id) = ctx.lookup_node_in_module(module, name) {
                (ctx.mib.tree().oid_of(node_id).to_vec(), 1)
            } else {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    defval_span,
                    format!("DEFVAL OID root {:?} could not be resolved", name),
                );
                return None;
            }
        }
        _ => {
            ctx.emit_diagnostic(
                crate::types::DiagCode::DefvalUnresolved,
                Some(ir_mod),
                defval_span,
                "DEFVAL OID value has no named root component".to_string(),
            );
            return None;
        }
    };

    for comp in &components[start_idx..] {
        match comp {
            ir::OidComponent::Number { value, .. } => arcs.push(*value),
            ir::OidComponent::NamedNumber { number, .. } => arcs.push(*number),
            ir::OidComponent::QualifiedNamedNumber { number, .. } => arcs.push(*number),
            ir::OidComponent::Name { name, .. } => {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    defval_span,
                    format!("DEFVAL OID component {:?} has no numeric value", name),
                );
                return None;
            }
            ir::OidComponent::QualifiedName { module, name, .. } => {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    defval_span,
                    format!(
                        "DEFVAL OID component {:?} has no numeric value",
                        format!("{module}.{name}")
                    ),
                );
                return None;
            }
        }
    }
    Some(Oid::from(arcs))
}

fn format_oid_components(components: &[ir::OidComponent]) -> String {
    let parts: Vec<String> = components
        .iter()
        .map(|c| match c {
            ir::OidComponent::Number { value, .. } => value.to_string(),
            ir::OidComponent::Name { name, .. } => name.clone(),
            ir::OidComponent::NamedNumber { name, number, .. } => {
                format!("{name}({number})")
            }
            ir::OidComponent::QualifiedName { module, name, .. } => {
                format!("{module}.{name}")
            }
            ir::OidComponent::QualifiedNamedNumber {
                module,
                name,
                number,
                ..
            } => format!("{module}.{name}({number})"),
        })
        .collect();
    format!("{{ {} }}", parts.join(" "))
}

fn hex_decode(s: &str) -> Vec<u8> {
    let mut clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if !clean.len().is_multiple_of(2) {
        clean.insert(0, '0');
    }
    let mut bytes = Vec::new();
    let mut digits = clean.bytes();
    while let Some(hi) = digits.next() {
        let lo = digits.next().unwrap_or(b'0');
        let hi = hex_nibble(hi).unwrap_or(0);
        let lo = hex_nibble(lo).unwrap_or(0);
        bytes.push((hi << 4) | lo);
    }
    bytes
}

fn hex_nibble(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

fn lookup_member_node(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
) -> Option<(NodeId, bool)> {
    if let Some(result) = ctx.lookup_node_for_module(ir_mod, name) {
        return Some(result);
    }
    if ctx.strictness.allow_global_fallbacks()
        && let Some(node_id) = ctx.lookup_node_global(name)
    {
        return Some((node_id, false));
    }
    None
}

fn is_notification_variation(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    supports_module: &str,
    var: &VariationData,
) -> bool {
    if let Some(node_id) = ctx.lookup_node_in_module(supports_module, &var.name) {
        return ctx.mib.tree().get(node_id).kind == Kind::Notification;
    }
    if let Some((node_id, _)) = ctx.lookup_node_for_module(ir_mod, &var.name) {
        return ctx.mib.tree().get(node_id).kind == Kind::Notification;
    }
    if ctx.strictness.allow_global_fallbacks()
        && let Some(node_id) = ctx.lookup_node_global(&var.name)
    {
        return ctx.mib.tree().get(node_id).kind == Kind::Notification;
    }

    var.syntax.is_none()
        && var.write_syntax.is_none()
        && var.creation_requires.is_empty()
        && var.defval.is_none()
}

fn binary_decode(s: &str, right_pad: bool) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| *c == '0' || *c == '1').collect();
    if clean.is_empty() {
        return Vec::new();
    }
    // Pad to byte boundary.
    let padded_len = clean.len().div_ceil(8) * 8;
    let padded = if right_pad {
        format!("{:0<width$}", clean, width = padded_len)
    } else {
        format!("{:0>width$}", clean, width = padded_len)
    };
    let mut bytes = Vec::new();
    for chunk in padded.as_bytes().chunks(8) {
        let s = std::str::from_utf8(chunk).unwrap_or("00000000");
        let byte = u8::from_str_radix(s, 2).unwrap_or(0);
        bytes.push(byte);
    }
    bytes
}

/// Check if a name refers to a SEQUENCE type definition (used to suppress
/// spurious unresolved type diagnostics for row SYNTAX references).
fn is_sequence_type_def(ctx: &ResolverContext, ir_mod: IrModuleId, name: &str) -> bool {
    fn has_sequence_def(m: &ir::Module, name: &str) -> bool {
        m.definitions.iter().any(|def| {
            if let ir::Definition::TypeDef(td) = def {
                td.name == name && matches!(td.syntax, ir::TypeSyntax::Sequence { .. })
            } else {
                false
            }
        })
    }

    let m = &ctx.modules[ir_mod.index()];
    if has_sequence_def(m, name) {
        return true;
    }
    if let Some(&source) = ctx
        .module_imports
        .get(&ir_mod)
        .and_then(|imps| imps.get(name))
    {
        let src_mod = &ctx.modules[source.index()];
        if has_sequence_def(src_mod, name) {
            return true;
        }
    }
    false
}

fn build_oid_refs(oid: &ir::OidAssignment) -> Vec<OidRef> {
    let mut refs = Vec::new();
    for comp in &oid.components {
        match comp {
            ir::OidComponent::Name { name, span } => {
                refs.push(OidRef {
                    name: name.clone(),
                    span: *span,
                });
            }
            ir::OidComponent::NamedNumber { name, span, .. } => {
                refs.push(OidRef {
                    name: name.clone(),
                    span: *span,
                });
            }
            ir::OidComponent::QualifiedName { name, span, .. } => {
                refs.push(OidRef {
                    name: name.clone(),
                    span: *span,
                });
            }
            ir::OidComponent::QualifiedNamedNumber { name, span, .. } => {
                refs.push(OidRef {
                    name: name.clone(),
                    span: *span,
                });
            }
            _ => {}
        }
    }
    refs
}

#[cfg(test)]
mod tests {
    use super::hex_decode;

    #[test]
    fn hex_decode_accepts_mixed_case_and_separators() {
        assert_eq!(hex_decode("'aF 0c'H"), vec![0xAF, 0x0C]);
    }

    #[test]
    fn hex_decode_pads_odd_digit_count() {
        assert_eq!(hex_decode("'ABC'H"), vec![0x0A, 0xBC]);
    }
}
