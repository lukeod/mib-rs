//! Phase 5: Semantic resolution.
//!
//! Transforms definitions into resolved semantic entities and attaches those
//! with resolved numeric identities to OID tree nodes:
//!
//! - Infers node kinds (table, row, column, scalar) from OBJECT-TYPE syntax.
//! - Creates [`Object`](super::super::object::ObjectData) entries with resolved
//!   types, access, status, indexes, and DEFVAL.
//! - Creates [`Notification`](super::super::notification::NotificationData),
//!   [`Group`](super::super::group::GroupData),
//!   [`Compliance`](super::super::compliance::ComplianceData), and
//!   [`Capability`](super::super::capability::CapabilityData) entries.
//! - Resolves AUGMENTS references, INDEX object linkage, and
//!   NOTIFICATION-TYPE OBJECTS references.

use std::collections::{HashMap, HashSet};

use crate::ir;
use crate::mib::Oid;
use crate::source::SourceRange;
use crate::types::{Access, BaseType, DiagCode, Kind, Status};
use tracing::trace;

use super::super::capability::CapabilityData;
use super::super::compliance::ComplianceData;
use super::super::group::GroupData;
use super::super::notification::NotificationData;
use super::super::object::ObjectData;
use super::super::typedef::TypeData;
use super::super::types::*;
use super::context::{IrModuleId, ResolverContext, UnresolvedReason};

/// Phase 5: Create resolved semantic entities from OID tree nodes.
///
/// Infers node kinds, creates objects/notifications/groups/compliances/capabilities,
/// resolves INDEX and AUGMENTS references, and validates table structure.
pub(super) fn resolve_semantics(ctx: &mut ResolverContext) {
    let declared_structures = collect_declared_object_structures(ctx);
    infer_node_kinds(ctx);
    create_resolved_objects(ctx, &declared_structures);
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
    // Track which module's OBJECT-TYPE determined each node's kind so
    // that only the preferred module's structural classification wins
    // when multiple modules define the same OID.
    let mut node_kind_module: HashMap<NodeId, ModuleId> = HashMap::new();
    let mut row_nodes: Vec<NodeId> = Vec::new();

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

            let existing_mod = node_kind_module.get(&node_id).copied();
            if !super::oids::should_prefer_module(ctx, existing_mod, ir_id) {
                continue;
            }

            let kind = if matches!(ot.syntax, ir::TypeSyntax::SequenceOf { .. }) {
                Kind::Table
            } else if !ot.index.is_empty() || !ot.augments.is_empty() {
                Kind::Row
            } else {
                Kind::Scalar
            };

            ctx.mib.tree.set_kind(node_id, kind);
            if kind == Kind::Row {
                row_nodes.push(node_id);
            }
            if let Some(&resolved_mod) = ctx.module_to_resolved.get(&ir_id) {
                node_kind_module.insert(node_id, resolved_mod);
            }
        }
    }

    // Reclassify children of Row nodes as columns.
    let mut seen: std::collections::HashSet<NodeId> = std::collections::HashSet::new();
    for node_id in &row_nodes {
        if !seen.insert(*node_id) {
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
fn create_resolved_objects(
    ctx: &mut ResolverContext,
    declared_structures: &HashMap<IrModuleId, DeclaredObjectStructure>,
) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::ObjectType(_)));
    ctx.mib.objects.reserve(work.len());

    let mut created_object_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];
        let ot = match &ctx.modules[mod_idx].definitions[def_idx] {
            ir::Definition::ObjectType(ot) => ot,
            _ => continue,
        };

        let node_id = ctx
            .module_symbol_to_node
            .get(&ir_id)
            .and_then(|syms| syms.get(&ot.name))
            .copied();

        // Extract all data from ot before mutable operations.
        let name = ot.name.clone();
        let range = ot.range;
        let status = ot.status;
        let description = ot.description.clone();
        let reference = ot.reference.clone();
        let status_range = ot.status_range;
        let description_range = ot.description_range;
        let reference_range = ot.reference_range;
        let access = ot.access;
        let units = ot.units.clone();
        let syntax_range = ot.syntax_range;
        let access_range = ot.access_range;
        let units_range = ot.units_range;
        let augments_range = ot.augments_range;
        let default_value_range = ot.defval_range;
        let syntax = ot.syntax.clone();
        let defval = ot.defval.clone();
        let oid = ot.oid.clone();

        let mut obj = ObjectData::new(name.clone());
        if let Some(structure) = declared_structures.get(&ir_id) {
            obj.declared_kind = structure.kind(&name);
            obj.declared_table_name = structure
                .row_to_table
                .get(&name)
                .cloned()
                .unwrap_or_default();
            obj.declared_row_name = structure
                .table_to_row
                .get(&name)
                .cloned()
                .unwrap_or_default();
            obj.declared_column_names = structure
                .row_to_columns
                .get(&name)
                .cloned()
                .unwrap_or_default();
            obj.declared_structure_error = structure.errors.get(&name).cloned().unwrap_or_default();
        }
        obj.entity.range = Some(range);
        obj.entity.node = node_id;
        obj.entity.module = Some(resolved_mod);
        obj.entity.status = status;
        obj.entity.description = description;
        obj.entity.reference = reference;
        obj.entity.status_range = status_range;
        obj.entity.description_range = description_range;
        obj.entity.reference_range = reference_range;
        obj.access = access;
        obj.units = units;
        obj.syntax_range = syntax_range;
        obj.access_range = access_range;
        obj.units_range = units_range;
        obj.augments_range = augments_range;
        obj.default_value_range = default_value_range;

        // Resolve type reference.
        let obj_name = obj.entity.name.clone();
        let resolved = resolve_type_syntax(ctx, ir_id, &syntax, &obj_name, syntax.range());
        obj.typ = resolved.type_id;
        let direct_values_are_bits = resolved.type_id.is_some_and(|type_id| {
            ctx.mib
                .raw()
                .type_(type_id)
                .effective_base(ctx.mib.types_slice())
                == BaseType::Bits
        });
        if direct_values_are_bits && resolved.bits.is_empty() {
            obj.declared_bits = resolved.enums.clone();
        } else {
            obj.declared_enums = resolved.enums.clone();
            obj.declared_bits = resolved.bits.clone();
        }
        obj.enums = resolved.enums;
        obj.bits = resolved.bits;
        if direct_values_are_bits && obj.bits.is_empty() {
            obj.bits = std::mem::take(&mut obj.enums);
        }
        obj.sizes = resolved.sizes;
        obj.ranges = resolved.ranges;
        obj.declared_sizes = resolved.declared_sizes;
        obj.declared_ranges = resolved.declared_ranges;
        obj.sizes_constrained = resolved.sizes_constrained;
        obj.ranges_constrained = resolved.ranges_constrained;

        // Convert DEFVAL.
        if let Some(dv) = &defval {
            obj.def_val = Some(convert_defval(
                ctx,
                ir_id,
                dv,
                obj.typ,
                obj.default_value_range.unwrap_or(range),
            ));
        }

        // Compute effective values from type chain.
        compute_effective_values(ctx, &mut obj);

        // Build OID refs from the OID assignment.
        obj.entity.oid_refs = ctx.build_oid_refs(ir_id, &oid);
        let parent_oid = obj
            .entity
            .node
            .and_then(|node| ctx.mib.tree().oid_of(node).parent());
        obj.declared_oid_parent = parent_oid.as_ref().and_then(|parent_oid| {
            obj.entity
                .oid_refs
                .iter()
                .rev()
                .find(|reference| reference.oid() == Some(parent_oid))
                .cloned()
        });

        // Store the declared row entry type name on table objects.
        if let ir::TypeSyntax::SequenceOf { entry_type, .. } = &syntax {
            obj.sequence_type_name = entry_type.clone();
        }

        let obj_id = ctx.mib.add_object(obj);

        // Attach to node - prefer SMIv2 modules when multiple modules
        // define the same OID (e.g., TCP-MIB and RFC1213-MIB both define
        // tcpConnTable). Compare the existing object's source module, not
        // the node's module from OID phase.
        if let Some(node_id) = node_id {
            let existing_obj = ctx.mib.tree().get(node_id).object;
            let existing_obj_mod = existing_obj.and_then(|oid| ctx.mib.raw().object(oid).module());
            if existing_obj.is_none()
                || super::oids::should_prefer_module(ctx, existing_obj_mod, ir_id)
            {
                ctx.mib.tree.attach_object(node_id, obj_id);
            }
        }

        // Register in module.
        ctx.mib.module_mut(resolved_mod).add_object(&name, obj_id);
        if let Some(node_id) = node_id {
            ctx.mib.module_mut(resolved_mod).add_node(&name, node_id);
        }
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

#[derive(Default)]
struct DeclaredObjectStructure {
    kinds: HashMap<String, Kind>,
    table_to_row: HashMap<String, String>,
    row_to_table: HashMap<String, String>,
    row_to_columns: HashMap<String, Vec<String>>,
    column_to_row: HashMap<String, String>,
    errors: HashMap<String, String>,
    #[cfg(test)]
    work_units: usize,
}

impl DeclaredObjectStructure {
    fn kind(&self, name: &str) -> Kind {
        self.kinds.get(name).copied().unwrap_or(Kind::Unknown)
    }

    fn mark_error(&mut self, name: &str, reason: impl Into<String>) {
        self.errors
            .entry(name.to_owned())
            .or_insert_with(|| reason.into());
    }
}

#[derive(Clone)]
struct ObjectShape {
    name: String,
    syntax_name: String,
    explicit_parent: String,
    oid: Option<Oid>,
    parent_oid: Option<Oid>,
    indexed: bool,
}

fn collect_declared_object_structures(
    ctx: &ResolverContext,
) -> HashMap<IrModuleId, DeclaredObjectStructure> {
    ctx.all_modules()
        .map(|(ir_mod, module)| (ir_mod, collect_module_object_structure(ctx, ir_mod, module)))
        .collect()
}

fn collect_module_object_structure(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    module: &ir::Module,
) -> DeclaredObjectStructure {
    let object_names = module
        .definitions
        .iter()
        .filter_map(|definition| match definition {
            ir::Definition::ObjectType(object) => Some(object.name.clone()),
            _ => None,
        })
        .collect::<HashSet<_>>();
    let mut structure = DeclaredObjectStructure::default();
    #[cfg(test)]
    {
        structure.work_units += module.definitions.len();
    }
    let mut objects = HashMap::with_capacity(object_names.len());
    let mut object_order = Vec::with_capacity(object_names.len());
    let mut sequence_fields = HashMap::<String, Vec<String>>::new();

    for definition in &module.definitions {
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        match definition {
            ir::Definition::TypeDef(typ) => {
                if let ir::TypeSyntax::Sequence { fields, .. } = &typ.syntax {
                    sequence_fields.insert(
                        typ.name.clone(),
                        fields.iter().map(|field| field.name.clone()).collect(),
                    );
                }
            }
            ir::Definition::ObjectType(object) => {
                let oid = ctx
                    .module_symbol_to_node
                    .get(&ir_mod)
                    .and_then(|symbols| symbols.get(&object.name))
                    .map(|node| ctx.mib.tree().oid_of(*node).clone());
                let parent_oid = oid.as_ref().and_then(Oid::parent);
                let explicit_parent =
                    declared_local_parent(&object.oid, module.name.as_str(), &object_names)
                        .unwrap_or_default();
                let syntax_name = declared_syntax_name(&object.syntax).unwrap_or_default();
                let indexed = !object.index.is_empty() || !object.augments.is_empty();
                let kind = if matches!(object.syntax, ir::TypeSyntax::SequenceOf { .. }) {
                    Kind::Table
                } else if indexed {
                    Kind::Row
                } else {
                    Kind::Scalar
                };
                structure.kinds.insert(object.name.clone(), kind);
                objects.insert(
                    object.name.clone(),
                    ObjectShape {
                        name: object.name.clone(),
                        syntax_name,
                        explicit_parent,
                        oid,
                        parent_oid,
                        indexed,
                    },
                );
                object_order.push(object.name.clone());
            }
            _ => {}
        }
    }

    let mut rows_by_explicit_table_and_syntax = HashMap::<(String, String), Vec<String>>::new();
    let mut rows_by_parent_oid_and_syntax = HashMap::<(Oid, String), Vec<String>>::new();
    for name in &object_order {
        let object = &objects[name];
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        if !object.explicit_parent.is_empty() && !object.syntax_name.is_empty() {
            rows_by_explicit_table_and_syntax
                .entry((object.explicit_parent.clone(), object.syntax_name.clone()))
                .or_default()
                .push(object.name.clone());
        }
        if let Some(parent_oid) = &object.parent_oid
            && !object.syntax_name.is_empty()
        {
            rows_by_parent_oid_and_syntax
                .entry((parent_oid.clone(), object.syntax_name.clone()))
                .or_default()
                .push(object.name.clone());
        }
    }

    #[cfg(test)]
    {
        structure.work_units += object_order.len();
    }
    let tables = object_order
        .iter()
        .map(|name| &objects[name])
        .filter(|object| structure.kind(&object.name) == Kind::Table)
        .cloned()
        .collect::<Vec<_>>();
    for table in &tables {
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        if table.syntax_name.is_empty() {
            continue;
        }
        let entry_type = table.syntax_name.as_str();
        let explicit_key = (table.name.clone(), entry_type.to_owned());
        let candidates = rows_by_explicit_table_and_syntax
            .get(&explicit_key)
            .or_else(|| {
                table.oid.as_ref().and_then(|oid| {
                    rows_by_parent_oid_and_syntax.get(&(oid.clone(), entry_type.to_owned()))
                })
            });
        match candidates.map(Vec::as_slice).unwrap_or_default() {
            [row] => link_table_row(&mut structure, &table.name, row),
            [] => structure.mark_error(
                &table.name,
                format!("has no exact row declaration for entry type {entry_type}"),
            ),
            rows => {
                structure.mark_error(
                    &table.name,
                    format!("has ambiguous row declarations: {}", rows.join(", ")),
                );
                for row in rows {
                    structure.mark_error(row, "is associated with multiple table declarations");
                }
            }
        }
    }

    // Indexed/AUGMENTS objects remain rows even when their table relationship
    // is malformed or unresolved. Structurally linked children of tables are
    // rows even when they omit INDEX/AUGMENTS.
    for name in &object_order {
        let object = &objects[name];
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        if object.indexed {
            structure.kinds.insert(object.name.clone(), Kind::Row);
        }
    }

    let row_names = structure
        .kinds
        .iter()
        .filter_map(|(name, kind)| (*kind == Kind::Row).then_some(name.clone()))
        .collect::<HashSet<_>>();
    #[cfg(test)]
    {
        structure.work_units += structure.kinds.len();
    }
    let row_order = object_order
        .iter()
        .filter(|name| row_names.contains(*name))
        .cloned()
        .collect::<Vec<_>>();
    #[cfg(test)]
    {
        structure.work_units += object_order.len();
    }
    let mut rows_by_oid = HashMap::<Oid, Vec<String>>::new();
    for row in &row_order {
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        if let Some(oid) = objects.get(row).and_then(|object| object.oid.clone()) {
            rows_by_oid.entry(oid).or_default().push(row.clone());
        }
    }

    for table in &tables {
        let Some(row) = structure.table_to_row.get(&table.name).cloned() else {
            continue;
        };
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        let Some(entry_type) = objects.get(&row).map(|object| object.syntax_name.as_str()) else {
            continue;
        };
        if let Some(fields) = sequence_fields.get(entry_type) {
            for field in fields {
                #[cfg(test)]
                {
                    structure.work_units += 1;
                }
                if objects.contains_key(field) {
                    link_row_column(&mut structure, &row, field);
                } else {
                    structure.mark_error(
                        &table.name,
                        format!("entry type {entry_type} names missing column {field}"),
                    );
                }
            }
        }
    }

    for name in &object_order {
        let object = &objects[name];
        #[cfg(test)]
        {
            structure.work_units += 1;
        }
        if row_names.contains(&object.explicit_parent) {
            link_row_column(&mut structure, &object.explicit_parent, &object.name);
            continue;
        }
        if let Some(parent_oid) = &object.parent_oid
            && let Some(rows) = rows_by_oid.get(parent_oid).map(Vec::as_slice)
        {
            match rows {
                [row] => link_row_column(&mut structure, row, &object.name),
                [] => {}
                rows => {
                    if !structure.column_to_row.contains_key(&object.name) {
                        structure.mark_error(
                            &object.name,
                            format!("has an ambiguous numeric row parent: {}", rows.join(", ")),
                        );
                        for row in rows {
                            structure.mark_error(
                                row,
                                format!("has ambiguous numeric child declaration {}", object.name),
                            );
                        }
                    }
                }
            }
        }
    }

    for columns in structure.row_to_columns.values_mut() {
        #[cfg(test)]
        {
            structure.work_units += columns.len();
        }
        let mut seen = HashSet::new();
        columns.retain(|column| seen.insert(column.clone()));
    }
    structure
}

fn declared_syntax_name(syntax: &ir::TypeSyntax) -> Option<String> {
    match syntax {
        ir::TypeSyntax::TypeRef { name, .. } => Some(name.clone()),
        ir::TypeSyntax::IntegerEnum { base, .. } if !base.is_empty() => Some(base.clone()),
        ir::TypeSyntax::Constrained { base, .. } => declared_syntax_name(base),
        ir::TypeSyntax::SequenceOf { entry_type, .. } => Some(entry_type.clone()),
        _ => None,
    }
}

fn declared_local_parent(
    oid: &ir::OidAssignment,
    module_name: &str,
    object_names: &HashSet<String>,
) -> Option<String> {
    oid.components.iter().rev().find_map(|component| {
        let name = match component {
            ir::OidComponent::Name { name, .. } | ir::OidComponent::NamedNumber { name, .. } => {
                name
            }
            ir::OidComponent::QualifiedName { module, name, .. }
            | ir::OidComponent::QualifiedNamedNumber { module, name, .. }
                if module == module_name =>
            {
                name
            }
            _ => return None,
        };
        object_names.contains(name).then(|| name.clone())
    })
}

fn link_table_row(structure: &mut DeclaredObjectStructure, table: &str, row: &str) {
    if let Some(existing) = structure.table_to_row.get(table)
        && existing != row
    {
        structure.mark_error(table, "has multiple exact row declarations");
        return;
    }
    if let Some(existing) = structure.row_to_table.get(row)
        && existing != table
    {
        structure.mark_error(row, "is associated with multiple table declarations");
        structure.mark_error(table, "shares its row with another table declaration");
        return;
    }
    structure
        .table_to_row
        .insert(table.to_owned(), row.to_owned());
    structure
        .row_to_table
        .insert(row.to_owned(), table.to_owned());
    structure.kinds.insert(row.to_owned(), Kind::Row);
}

fn link_row_column(structure: &mut DeclaredObjectStructure, row: &str, column: &str) {
    if row == column {
        structure.mark_error(row, "cannot use a row declaration as its own column");
        return;
    }
    if matches!(structure.kind(column), Kind::Table | Kind::Row) {
        structure.mark_error(
            row,
            format!("uses table or row declaration {column} as a sequence field"),
        );
        structure.mark_error(column, "is used as a column by conflicting topology");
        return;
    }
    if let Some(existing) = structure.column_to_row.get(column)
        && existing != row
    {
        let existing = existing.clone();
        structure.mark_error(
            row,
            format!("shares column declaration {column} with row {existing}"),
        );
        structure.mark_error(
            &existing,
            format!("shares column declaration {column} with row {row}"),
        );
        structure.mark_error(column, "is linked to multiple row declarations");
        return;
    }
    structure
        .column_to_row
        .insert(column.to_owned(), row.to_owned());
    structure.kinds.insert(column.to_owned(), Kind::Column);
    structure
        .row_to_columns
        .entry(row.to_owned())
        .or_default()
        .push(column.to_owned());
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
    range: SourceRange,
) -> SyntaxConstraints {
    let mut sc = SyntaxConstraints {
        type_id: None,
        sizes: Vec::new(),
        declared_sizes: Vec::new(),
        sizes_constrained: false,
        ranges: Vec::new(),
        declared_ranges: Vec::new(),
        ranges_constrained: false,
        enums: Vec::new(),
        bits: Vec::new(),
    };
    resolve_type_syntax_into(ctx, ir_mod, syntax, referrer, range, &mut sc);
    if let Some(type_id) = sc.type_id {
        let typ = ctx.mib.raw().type_(type_id);
        let types = ctx.mib.types_slice();
        if sc.sizes_constrained {
            let inherited = inline_parent_constraint(typ, types, true);
            if inherited.present {
                sc.sizes = if inherited.values.is_empty() {
                    Vec::new()
                } else {
                    super::types::intersect_constraints(&sc.sizes, &inherited.values)
                };
            }
        }
        if sc.ranges_constrained {
            let inherited = inline_parent_constraint(typ, types, false);
            if inherited.present {
                sc.ranges = if inherited.values.is_empty() {
                    Vec::new()
                } else {
                    super::types::intersect_constraints(&sc.ranges, &inherited.values)
                };
            }
        }
    }
    sc
}

fn resolve_type_syntax_into(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    syntax: &ir::TypeSyntax,
    referrer: &str,
    range: SourceRange,
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
                ctx.record_unresolved_type(
                    referrer,
                    name,
                    &mod_name,
                    UnresolvedReason::TypeNotFound,
                    ir_mod,
                    range,
                );
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
                    ctx.record_unresolved_type(
                        referrer,
                        base,
                        &mod_name,
                        UnresolvedReason::TypeNotFound,
                        ir_mod,
                        range,
                    );
                }
            } else {
                sc.type_id = lookup_primitive_type(ctx, ir_mod, range, referrer, "INTEGER");
            }
            sc.enums = named_numbers
                .iter()
                .map(|nn| NamedValue {
                    label: nn.name.clone(),
                    value: nn.value,
                    range: nn.range,
                })
                .collect();
        }
        ir::TypeSyntax::Bits { named_bits, .. } => {
            sc.type_id = lookup_primitive_type(ctx, ir_mod, range, referrer, "BITS");
            sc.bits = named_bits
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
            resolve_type_syntax_into(ctx, ir_mod, base, referrer, range, sc);
            match constraint {
                ir::Constraint::Size { ranges, .. } => {
                    sc.sizes = ranges.iter().map(super::types::resolve_range).collect();
                    sc.declared_sizes = sc.sizes.clone();
                    sc.sizes_constrained = true;
                }
                ir::Constraint::Range { ranges, .. } => {
                    sc.ranges = ranges.iter().map(super::types::resolve_range).collect();
                    sc.declared_ranges = sc.ranges.clone();
                    sc.ranges_constrained = true;
                }
            }
        }
        ir::TypeSyntax::SequenceOf { .. } | ir::TypeSyntax::Sequence { .. } => {}
        ir::TypeSyntax::OctetString { .. } => {
            sc.type_id = lookup_primitive_type(ctx, ir_mod, range, referrer, "OCTET STRING");
        }
        ir::TypeSyntax::ObjectIdentifier { .. } => {
            sc.type_id = lookup_primitive_type(ctx, ir_mod, range, referrer, "OBJECT IDENTIFIER");
        }
    }
}

fn lookup_primitive_type(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    range: SourceRange,
    referrer: &str,
    name: &str,
) -> Option<TypeId> {
    if let Some((type_id, _)) = ctx.lookup_type_for_module(ir_mod, name) {
        return Some(type_id);
    }
    ctx.emit_diagnostic(
        DiagCode::PrimitiveTypeMissing,
        Some(ir_mod),
        Some(range),
        format!("primitive type {name} not found for {referrer:?}"),
    );
    None
}

struct InlineParentConstraint {
    values: Vec<Range>,
    present: bool,
}

fn inline_parent_constraint(
    typ: &TypeData,
    types: &[TypeData],
    is_size: bool,
) -> InlineParentConstraint {
    let (values, present) = if is_size {
        (
            typ.effective_sizes(types),
            typ.effective_sizes_constrained(),
        )
    } else {
        (
            typ.effective_ranges(types),
            typ.effective_ranges_constrained(),
        )
    };
    if present {
        return InlineParentConstraint {
            values: values.to_vec(),
            present: true,
        };
    }

    let base = typ.effective_base(types);
    match super::types::base_constraint(base, is_size) {
        Some(range) => InlineParentConstraint {
            values: vec![range],
            present: true,
        },
        None => InlineParentConstraint {
            values: Vec::new(),
            present: false,
        },
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

    // Inline constraints were narrowed while resolving syntax. Absent inline
    // constraints inherit the type's effective constraint directly. Presence
    // is tracked separately because an empty intersection is still constrained.
    if !obj.sizes_constrained {
        obj.sizes = t.effective_sizes(types).to_vec();
        obj.sizes_constrained = t.effective_sizes_constrained();
    }
    if !obj.ranges_constrained {
        obj.ranges = t.effective_ranges(types).to_vec();
        obj.ranges_constrained = t.effective_ranges_constrained();
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

        let work: Vec<(String, Vec<ir::definition::IndexItem>, String, SourceRange)> = ctx.modules
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
                        ot.augments_range.unwrap_or(ot.range),
                    ))
                }
                _ => None,
            })
            .collect();

        for (name, index_items, augments, augments_range) in work {
            if !index_items.is_empty() {
                for item in &index_items {
                    if is_bare_type_index(&item.object) {
                        continue;
                    }
                    if lookup_object_by_name(ctx, ir_id, &item.object).is_some() {
                        continue;
                    }
                    if ctx.lookup_node_for_module(ir_id, &item.object).is_some() {
                        ctx.emit_diagnostic(
                            DiagCode::IndexNotObject,
                            Some(ir_id),
                            Some(item.range),
                            format!(
                                "INDEX {:?} of {:?} resolves to a node without an object definition",
                                item.object, name
                            ),
                        );
                    } else {
                        let mod_name = ctx.modules[mod_idx].name.clone();
                        ctx.record_unresolved_index(
                            &name,
                            &item.object,
                            &mod_name,
                            ir_id,
                            item.range,
                        );
                    }
                }
            }

            if !augments.is_empty() && lookup_object_by_name(ctx, ir_id, &augments).is_none() {
                if ctx.lookup_node_for_module(ir_id, &augments).is_some() {
                    ctx.emit_diagnostic(
                        DiagCode::AugmentsNotObject,
                        Some(ir_id),
                        Some(augments_range),
                        format!(
                            "AUGMENTS target {:?} of {:?} resolves to a node without an object definition",
                            augments, name
                        ),
                    );
                } else {
                    let mod_name = ctx.modules[mod_idx].name.clone();
                    ctx.record_unresolved_oid(
                        &name,
                        &augments,
                        &mod_name,
                        UnresolvedReason::AugmentsTargetNotFound,
                        ir_id,
                        augments_range,
                    );
                }
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
            && let Some(target_obj_id) = lookup_object_by_name(ctx, ir_id, &augments)
        {
            ctx.mib.object_mut(obj_id).augments = Some(target_obj_id);
            ctx.mib.object_mut(target_obj_id).augmented_by.push(obj_id);
        }
    }
}

fn check_augments_nesting(ctx: &mut ResolverContext) {
    for mod_idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(mod_idx as u32);
        let work: Vec<(String, String, SourceRange)> = ctx.modules[mod_idx]
            .definitions
            .iter()
            .filter_map(|def| match def {
                ir::Definition::ObjectType(ot) if !ot.augments.is_empty() => {
                    Some((ot.name.clone(), ot.augments.clone(), ot.range))
                }
                _ => None,
            })
            .collect();

        for (name, augments, range) in work {
            let Some(obj_id) = lookup_object_in_module_scope(ctx, ir_id, &name) else {
                continue;
            };
            let Some(target_obj_id) = ctx.mib.raw().object(obj_id).augments() else {
                continue;
            };
            if ctx.mib.raw().object(target_obj_id).augments().is_some() {
                ctx.emit_diagnostic(
                    DiagCode::AugmentNested,
                    Some(ir_id),
                    Some(range),
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
        let type_id = ctx
            .lookup_type_for_module(ir_mod, &item.object)
            .map(|(id, _)| id);
        let (base, sizes) = if let Some(type_id) = type_id {
            let td = ctx.mib.raw().type_(type_id);
            (
                td.effective_base(ctx.mib.types_slice()),
                td.effective_sizes(ctx.mib.types_slice()),
            )
        } else {
            (BaseType::Unknown, &[][..])
        };
        return Some(IndexEntry {
            name: item.object.clone(),
            object: None,
            type_id,
            implied: item.implied,
            encoding: classify_index_encoding(base, item.implied, sizes),
            range: item.range,
        });
    }

    // Diagnostic for unresolved INDEX is emitted by validate_table_semantics.
    let Some(obj_id) = lookup_object_by_name(ctx, ir_mod, &item.object) else {
        return Some(IndexEntry {
            name: item.object.clone(),
            object: None,
            type_id: None,
            implied: item.implied,
            encoding: crate::types::IndexEncoding::Unknown,
            range: item.range,
        });
    };
    let o = ctx.mib.raw().object(obj_id);
    let type_id = o.typ;
    let base = o.typ.map_or(BaseType::Unknown, |tid| {
        ctx.mib
            .raw()
            .type_(tid)
            .effective_base(ctx.mib.types_slice())
    });
    let encoding = classify_index_encoding(base, item.implied, o.effective_sizes());

    Some(IndexEntry {
        name: item.object.clone(),
        object: Some(obj_id),
        type_id,
        implied: item.implied,
        encoding,
        range: item.range,
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
        && let Some(obj_id) = ctx.mib.object_by_name(name)
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
        return Some(obj_id);
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
    ctx.mib.notifications.reserve(work.len());

    let mut created_notification_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        // Extract data before mutable operations.
        let (name, range, objects, status, description, reference, trap_info, oid) = {
            let notif = match &ctx.modules[mod_idx].definitions[def_idx] {
                ir::Definition::Notification(n) => n,
                _ => continue,
            };
            (
                notif.name.clone(),
                notif.range,
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
        nd.entity.range = Some(range);
        nd.entity.node = Some(node_id);
        nd.entity.module = Some(resolved_mod);
        nd.entity.status = status;
        nd.entity.description = description;
        nd.entity.reference = reference;

        // Resolve OBJECTS list.
        for obj_name in &objects {
            let obj = lookup_notification_object(ctx, ir_id, obj_name);
            if let Some(obj_id) = obj.object {
                if ctx.mib.raw().object(obj_id).access() == Access::NotAccessible {
                    ctx.emit_diagnostic(
                        DiagCode::NotifObjectAccess,
                        Some(ir_id),
                        Some(range),
                        format!(
                            "notification {:?} references {:?} which is not-accessible",
                            name, obj_name
                        ),
                    );
                }
                nd.objects.push(obj_id);
            } else if obj.node_found {
                ctx.emit_diagnostic(
                    DiagCode::NotifObjectNotObject,
                    Some(ir_id),
                    Some(range),
                    format!(
                        "notification {:?} references {:?} which is not an object definition",
                        name, obj_name
                    ),
                );
            } else {
                let mod_name = ctx.modules[mod_idx].name.clone();
                ctx.record_unresolved_notification_object(&name, obj_name, &mod_name, ir_id, range);
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
            nd.entity.oid_refs = ctx.build_oid_refs(ir_id, oid);
        }

        let notif_id = ctx.mib.add_notification(nd);

        let existing = ctx.mib.tree().get(node_id).notification;
        let existing_mod = existing.and_then(|id| ctx.mib.raw().notification(id).module());
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
    ctx.mib.groups.reserve(work.len());

    let mut created_group_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        let (name, range, members, status, description, reference, oid, is_notif) = {
            let def = &ctx.modules[mod_idx].definitions[def_idx];
            match def {
                ir::Definition::ObjectGroup(g) => (
                    g.name.clone(),
                    g.range,
                    g.objects.clone(),
                    g.status,
                    g.description.clone(),
                    g.reference.clone(),
                    g.oid.clone(),
                    false,
                ),
                ir::Definition::NotificationGroup(g) => (
                    g.name.clone(),
                    g.range,
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
        gd.entity.range = Some(range);
        gd.entity.node = Some(node_id);
        gd.entity.module = Some(resolved_mod);
        gd.entity.status = status;
        gd.entity.description = description;
        gd.entity.reference = reference;
        gd.is_notification_group = is_notif;
        gd.entity.oid_refs = ctx.build_oid_refs(ir_id, &oid);

        let mut has_objects = false;
        let mut has_notifications = false;

        // Resolve members.
        for member in &members {
            let member_name = &member.name;
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
                            Some(member.range),
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
                            Some(member.range),
                            format!(
                                "object group {:?} includes notification {:?}",
                                name, member_name
                            ),
                        );
                    } else if kind.is_object_type() {
                        has_objects = true;
                    }

                    if let Some(obj_id) = object_id
                        && ctx.mib.raw().object(obj_id).access() == Access::NotAccessible
                    {
                        ctx.emit_diagnostic(
                            DiagCode::GroupNotAccessible,
                            Some(ir_id),
                            Some(member.range),
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
                    member.range,
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
                    Some(member.range),
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
                Some(range),
                format!(
                    "group {:?} contains scalars/columns and notifications",
                    name
                ),
            );
        }

        let group_id = ctx.mib.add_group(gd);

        let existing = ctx.mib.tree().get(node_id).group;
        let existing_mod = existing.and_then(|id| ctx.mib.raw().group(id).module());
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
        return Some(ctx.mib.raw().object(obj_id).status());
    }
    if let Some(notif_id) = node.notification {
        return Some(ctx.mib.raw().notification(notif_id).status());
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

struct NotificationObjectLookup {
    object: Option<ObjectId>,
    node_found: bool,
}

fn lookup_notification_object(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
) -> NotificationObjectLookup {
    if let Some(obj_id) = lookup_object_in_module_scope(ctx, ir_mod, name) {
        return NotificationObjectLookup {
            object: Some(obj_id),
            node_found: true,
        };
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
            fallback = "global_node_lookup",
            "resolved notification object node via global fallback",
        );
        return NotificationObjectLookup {
            object: ctx.mib.tree().get(node_id).object(),
            node_found: true,
        };
    }

    if let Some((node_id, used_import)) = ctx.lookup_node_for_module(ir_mod, name) {
        if used_import {
            ctx.mark_import_used(ir_mod, name);
        }
        return NotificationObjectLookup {
            object: ctx.mib.tree().get(node_id).object(),
            node_found: true,
        };
    }

    NotificationObjectLookup {
        object: None,
        node_found: false,
    }
}

fn check_group_member_status(
    ctx: &mut ResolverContext,
    ir_id: IrModuleId,
    range: SourceRange,
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
            Some(range),
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
    ctx.mib.compliances.reserve(work.len());

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
            range: SourceRange,
        }
        struct CompModData {
            module_name: String,
            mandatory_groups: Vec<String>,
            groups: Vec<ComplianceGroup>,
            objects: Vec<CompObjData>,
            range: SourceRange,
        }

        let (name, range, status, description, reference, oid, ir_mod_name, comp_mod_data): (
            String,
            SourceRange,
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
                mc.range,
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
                                range: g.range,
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
                                range: o.range,
                            })
                            .collect();
                        CompModData {
                            module_name,
                            mandatory_groups: cm.mandatory_groups.clone(),
                            groups,
                            objects,
                            range: cm.range,
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
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &o.object, o.range));
                    let resolved_write_syntax = o
                        .write_syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &o.object, o.range));
                    ComplianceObject {
                        object: o.object.clone(),
                        syntax: resolved_syntax,
                        write_syntax: resolved_write_syntax,
                        min_access: o.min_access,
                        description: o.description.clone(),
                        range: o.range,
                    }
                })
                .collect();

            comp_modules.push(ComplianceModule {
                module_name: cmd.module_name.clone(),
                mandatory_groups: cmd.mandatory_groups.clone(),
                groups: cmd.groups.clone(),
                objects,
                range: cmd.range,
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
        cd.entity.range = Some(range);
        cd.entity.node = Some(node_id);
        cd.entity.module = Some(resolved_mod);
        cd.entity.status = status;
        cd.entity.description = description;
        cd.entity.reference = reference;
        cd.entity.oid_refs = ctx.build_oid_refs(ir_id, &oid);
        cd.modules = comp_modules;

        let comp_id = ctx.mib.add_compliance(cd);

        let existing = ctx.mib.tree().get(node_id).compliance;
        let existing_mod = existing.and_then(|id| ctx.mib.raw().compliance(id).module());
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
    range: SourceRange,
    creation_requires: Vec<ir::NameRef>,
    defval: Option<ir::syntax::DefVal>,
}

/// Create resolved Capability instances.
fn create_resolved_capabilities(ctx: &mut ResolverContext) {
    let work = ctx.collect_definitions(|def| matches!(def, ir::Definition::AgentCapabilities(_)));
    ctx.mib.capabilities.reserve(work.len());

    let mut created_capability_count = 0;
    for (mod_idx, def_idx) in work {
        let ir_id = IrModuleId(mod_idx as u32);
        let resolved_mod = ctx.module_to_resolved[&ir_id];

        // Pre-extract capability support data in a scoped borrow so later
        // resolution work can mutate ctx without borrow-ending placeholders.
        struct SupportsData {
            module_name: String,
            includes: Vec<ir::NameRef>,
            variations: Vec<VariationData>,
            range: SourceRange,
        }

        let (name, range, status, description, reference, product_release, oid, supports_data): (
            String,
            SourceRange,
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
                ac.range,
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
                                range: v.range,
                                creation_requires: v.creation_requires.clone(),
                                defval: v.defval.clone(),
                            })
                            .collect(),
                        range: sm.range,
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
        cap.entity.range = Some(range);
        cap.entity.node = Some(node_id);
        cap.entity.module = Some(resolved_mod);
        cap.entity.status = status;
        cap.entity.description = description;
        cap.entity.reference = reference;
        cap.product_release = product_release;
        cap.entity.oid_refs = ctx.build_oid_refs(ir_id, &oid);

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
                            Some(var.range),
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
                        range: var.range,
                    });
                } else {
                    let syntax = var
                        .syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &var.name, var.range));
                    let write_syntax = var
                        .write_syntax
                        .as_ref()
                        .map(|s| resolve_type_syntax(ctx, ir_id, s, &var.name, var.range));
                    // For defval, derive the type from the resolved syntax if
                    // present, otherwise fall back to None.
                    let defval_typ = syntax.as_ref().and_then(|sc| sc.type_id);
                    let def_val = var
                        .defval
                        .as_ref()
                        .map(|dv| convert_defval(ctx, ir_id, dv, defval_typ, var.range));
                    obj_vars.push(ObjectVariation {
                        object: var.name.clone(),
                        syntax,
                        write_syntax,
                        access: var.access,
                        creation_requires: var
                            .creation_requires
                            .iter()
                            .map(|reference| {
                                ctx.supports_oid_ref(
                                    ir_id,
                                    &sd.module_name,
                                    &reference.name,
                                    reference.range,
                                )
                            })
                            .collect(),
                        def_val,
                        description: var.description.clone(),
                        range: var.range,
                    });
                }
            }

            cap.supports.push(CapabilitiesModule {
                module_name: sd.module_name.clone(),
                includes: sd
                    .includes
                    .iter()
                    .map(|reference| reference.name.clone())
                    .collect(),
                object_variations: obj_vars,
                notification_variations: notif_vars,
                range: sd.range,
            });
        }

        let cap_id = ctx.mib.add_capability(cap);

        let existing = ctx.mib.tree().get(node_id).capability;
        let existing_mod = existing.and_then(|id| ctx.mib.raw().capability(id).module());
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
    defval_range: SourceRange,
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
                    Some(defval_range),
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
                    Some(defval_range),
                    format!("binary DEFVAL contains non-binary digits: {raw:?}"),
                );
            }
            let is_bits = typ.is_some_and(|tid| {
                let base = ctx
                    .mib
                    .raw()
                    .type_(tid)
                    .effective_base(ctx.mib.types_slice());
                base == BaseType::Bits
            });
            let bytes = binary_decode(s, is_bits);
            DefVal::bytes(bytes, raw)
        }
        ir::syntax::DefVal::Enum(label) => {
            // Check if this is an OID reference by checking the object's base type.
            let is_oid = typ.is_some_and(|tid| {
                let base = ctx
                    .mib
                    .raw()
                    .type_(tid)
                    .effective_base(ctx.mib.types_slice());
                base == BaseType::ObjectIdentifier
            });
            if is_oid {
                // Try to look up as an OID reference.
                if let Some((node_id, used_import)) = ctx.lookup_node_for_module(ir_mod, label) {
                    if used_import {
                        ctx.mark_import_used(ir_mod, label);
                    }
                    let oid = ctx.mib.tree().oid_of(node_id).clone();
                    let reference = ctx.oid_ref_for_name(ir_mod, label, defval_range);
                    return DefVal::oid_with_ref(oid, label.clone(), reference);
                }
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    Some(defval_range),
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
                let reference = ctx.oid_ref_for_name(ir_mod, name, defval_range);
                DefVal::oid_with_ref(oid, name.clone(), reference)
            } else {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    Some(defval_range),
                    format!("DEFVAL OID reference {:?} could not be resolved", name),
                );
                DefVal::unset()
            }
        }
        ir::syntax::DefVal::OidValue { components } => {
            // Try to resolve the OID from components.
            let raw = format_oid_components(components);
            if let Some(oid) = resolve_defval_oid(ctx, ir_mod, components, defval_range) {
                let references = ctx.build_oid_component_refs(ir_mod, components);
                if components.len() == 1
                    && let [reference] = references.as_slice()
                    && reference.oid() == Some(&oid)
                {
                    DefVal::oid_with_ref(oid, raw, reference.clone())
                } else {
                    DefVal::oid(oid, raw)
                }
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
    defval_range: SourceRange,
) -> Option<Oid> {
    if components.is_empty() {
        ctx.emit_diagnostic(
            crate::types::DiagCode::DefvalUnresolved,
            Some(ir_mod),
            Some(defval_range),
            "DEFVAL OID value has no components".to_string(),
        );
        return None;
    }

    let (mut arcs, start_idx) = match &components[0] {
        ir::OidComponent::Name { name, .. } | ir::OidComponent::NamedNumber { name, .. } => {
            if let Some((node_id, used_import)) = ctx.lookup_node_for_module(ir_mod, name) {
                if used_import {
                    ctx.mark_import_used(ir_mod, name);
                }
                (ctx.mib.tree().oid_of(node_id).to_vec(), 1)
            } else {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    Some(defval_range),
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
                    Some(defval_range),
                    format!("DEFVAL OID root {:?} could not be resolved", name),
                );
                return None;
            }
        }
        _ => {
            ctx.emit_diagnostic(
                crate::types::DiagCode::DefvalUnresolved,
                Some(ir_mod),
                Some(defval_range),
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
                    Some(defval_range),
                    format!("DEFVAL OID component {:?} has no numeric value", name),
                );
                return None;
            }
            ir::OidComponent::QualifiedName { module, name, .. } => {
                ctx.emit_diagnostic(
                    crate::types::DiagCode::DefvalUnresolved,
                    Some(ir_mod),
                    Some(defval_range),
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        collect_module_object_structure, hex_decode, resolve_defval_oid, resolve_type_syntax,
    };
    use crate::ir::{self, Module};
    use crate::mib::resolver::context::{IrModuleId, ResolverContext};
    use crate::mib::typedef::TypeData;
    use crate::source::{SourceOrigin, SourceRange, SourceSet};
    use crate::types::{DiagCode, DiagnosticConfig, ResolverStrictness};

    fn test_context(
        strictness: ResolverStrictness,
        config: DiagnosticConfig,
    ) -> (ResolverContext, SourceRange) {
        let mut sources = SourceSet::new();
        let id = sources
            .insert(
                SourceOrigin::memory("resolver-test"),
                "resolver-test",
                Arc::from(&b"test"[..]),
            )
            .unwrap();
        let range = sources.get(id).unwrap().range(0..4).unwrap();
        (ResolverContext::new(strictness, config, sources), range)
    }

    fn primitive_syntaxes(range: SourceRange) -> Vec<(&'static str, ir::TypeSyntax)> {
        vec![
            (
                "INTEGER",
                ir::TypeSyntax::IntegerEnum {
                    base: String::new(),
                    base_range: None,
                    named_numbers: Vec::new(),
                    range,
                },
            ),
            (
                "BITS",
                ir::TypeSyntax::Bits {
                    named_bits: Vec::new(),
                    range,
                },
            ),
            ("OCTET STRING", ir::TypeSyntax::OctetString { range }),
            (
                "OBJECT IDENTIFIER",
                ir::TypeSyntax::ObjectIdentifier { range },
            ),
        ]
    }

    #[test]
    fn compound_oid_defval_marks_only_unqualified_imports_used() {
        let (mut ctx, range) =
            test_context(ResolverStrictness::Permissive, DiagnosticConfig::silent());
        ctx.modules = vec![
            Module::new("IMPORTER-MIB".to_string(), Some(range)),
            Module::new("SOURCE-MIB".to_string(), Some(range)),
        ];
        let importer = IrModuleId(0);
        let source = IrModuleId(1);
        ctx.module_index
            .insert("SOURCE-MIB".to_string(), vec![source]);

        let tree = &mut ctx.mib.tree;
        let tree_root = tree.root();
        let root = tree.get_or_create_child(tree_root, 1);
        tree.set_name(root, "importedRoot".to_string());
        ctx.module_symbol_to_node
            .entry(source)
            .or_default()
            .insert("importedRoot".to_string(), root);
        ctx.module_imports
            .entry(importer)
            .or_default()
            .insert("importedRoot".to_string(), source);

        let unqualified = [
            ir::OidComponent::Name {
                name: "importedRoot".to_string(),
                range,
            },
            ir::OidComponent::Number { value: 42, range },
        ];
        let oid = resolve_defval_oid(&mut ctx, importer, &unqualified, range)
            .expect("unqualified imported root should resolve");
        assert_eq!(oid.to_string(), "1.42");
        assert!(
            ctx.used_imports
                .get(&importer)
                .is_some_and(|used| used.contains("importedRoot"))
        );

        ctx.used_imports.clear();
        let qualified = [
            ir::OidComponent::QualifiedName {
                module: "SOURCE-MIB".to_string(),
                name: "importedRoot".to_string(),
                range,
            },
            ir::OidComponent::Number { value: 7, range },
        ];
        let oid = resolve_defval_oid(&mut ctx, importer, &qualified, range)
            .expect("qualified root should resolve");
        assert_eq!(oid.to_string(), "1.7");
        assert!(!ctx.used_imports.contains_key(&importer));
    }

    #[test]
    fn hex_decode_accepts_mixed_case_and_separators() {
        assert_eq!(hex_decode("'aF 0c'H"), vec![0xAF, 0x0C]);
    }

    #[test]
    fn hex_decode_pads_odd_digit_count() {
        assert_eq!(hex_decode("'ABC'H"), vec![0x0A, 0xBC]);
    }

    #[test]
    fn missing_primitive_types_emit_diagnostics() {
        let (_, range) = test_context(ResolverStrictness::Normal, DiagnosticConfig::verbose());
        for (name, syntax) in primitive_syntaxes(range) {
            let (mut ctx, range) =
                test_context(ResolverStrictness::Normal, DiagnosticConfig::verbose());
            ctx.modules = vec![Module::new("TEST-MIB".to_string(), Some(range))];

            let constraints =
                resolve_type_syntax(&mut ctx, IrModuleId(0), &syntax, "testObject", range);

            assert!(constraints.type_id.is_none(), "primitive {name}");
            let diagnostics = ctx.mib.diagnostics();
            assert_eq!(diagnostics.len(), 1, "primitive {name}");
            assert_eq!(diagnostics[0].code, DiagCode::PrimitiveTypeMissing);
            assert_eq!(diagnostics[0].module.as_deref(), Some("TEST-MIB"));
            assert_eq!(
                diagnostics[0].message,
                format!("primitive type {name} not found for \"testObject\"")
            );
        }
    }

    #[test]
    fn primitive_type_lookup_preserves_resolved_type() {
        let ir_mod = IrModuleId(0);
        let (mut ctx, range) =
            test_context(ResolverStrictness::Normal, DiagnosticConfig::verbose());
        ctx.modules = vec![Module::new("TEST-MIB".to_string(), Some(range))];

        for (name, _) in primitive_syntaxes(range) {
            let type_id = ctx.mib.add_type(TypeData::new(name.to_string()));
            ctx.module_symbol_to_type
                .entry(ir_mod)
                .or_default()
                .insert(name.to_string(), type_id);
        }

        for (name, syntax) in primitive_syntaxes(range) {
            let expected = ctx.module_symbol_to_type[&ir_mod][name];
            let constraints = resolve_type_syntax(&mut ctx, ir_mod, &syntax, "testObject", range);

            assert_eq!(constraints.type_id, Some(expected), "primitive {name}");
        }
        assert!(ctx.mib.diagnostics().is_empty());
    }

    #[test]
    fn declared_structure_indexing_has_linear_work_bound() {
        fn measure(tables: usize) -> (usize, usize) {
            let mut source = String::from(
                "STRUCTURE-WORK-MIB DEFINITIONS ::= BEGIN\nroot OBJECT IDENTIFIER ::= { 1 3 6 }\n",
            );
            for index in 0..tables {
                source.push_str(&format!(
                    "t{index} OBJECT-TYPE SYNTAX SEQUENCE OF E{index} ACCESS not-accessible STATUS mandatory ::= {{ root {} }}\n",
                    index + 1
                ));
                source.push_str(&format!(
                    "e{index} OBJECT-TYPE SYNTAX E{index} ACCESS not-accessible STATUS mandatory INDEX {{ c{index} }} ::= {{ t{index} 1 }}\n"
                ));
                source.push_str(&format!(
                    "c{index} OBJECT-TYPE SYNTAX INTEGER ACCESS read-only STATUS mandatory ::= {{ e{index} 1 }}\n"
                ));
                source.push_str(&format!("E{index} ::= SEQUENCE {{ c{index} INTEGER }}\n"));
            }
            source.push_str("END\n");

            let mut sources = SourceSet::new();
            let source_id = sources
                .insert(
                    SourceOrigin::memory("structure-work"),
                    "structure-work",
                    Arc::from(source.into_bytes()),
                )
                .unwrap();
            let config = DiagnosticConfig::silent();
            let document = sources.get(source_id).unwrap();
            let parsed = crate::parser::parse(document, &config)
                .into_iter()
                .next()
                .unwrap();
            let module = crate::lower::lower(parsed, document, &config);
            let definition_count = module.definitions.len();
            let ctx = ResolverContext::new(ResolverStrictness::Normal, config, sources);
            let structure = collect_module_object_structure(&ctx, IrModuleId(0), &module);
            assert_eq!(structure.table_to_row.len(), tables);
            assert_eq!(structure.row_to_columns.len(), tables);
            assert!(structure.work_units <= definition_count * 8);
            (definition_count, structure.work_units)
        }

        let (small_definitions, small_work) = measure(64);
        let (large_definitions, large_work) = measure(128);
        assert_eq!(large_definitions, small_definitions * 2 - 1);
        assert!(large_work <= small_work * 2);
    }
}
