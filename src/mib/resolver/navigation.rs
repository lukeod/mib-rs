//! Build module-local source span indexes after semantic resolution.

use crate::ir;
use crate::mib::navigation::{SemanticSpanEntry, SemanticSpanIndex, SemanticSpanKind};
use crate::source::SourceRange;

use super::super::{ModuleId, NodeId, Symbol};
use super::context::{IrModuleId, ResolverContext};

#[derive(Clone, Copy, Default)]
struct Identity {
    symbol: Option<Symbol>,
    module: Option<ModuleId>,
}

pub(super) fn build_semantic_span_indexes(ctx: &mut ResolverContext) {
    let indexes: Vec<(ModuleId, SemanticSpanIndex)> = ctx
        .all_modules()
        .filter_map(|(ir_id, module)| {
            let resolved_id = ctx.module_to_resolved.get(&ir_id).copied()?;
            let mut entries = Vec::new();

            for definition in &module.definitions {
                let symbol = ctx.mib.module_data(resolved_id).symbol(definition.name());
                entries.push(SemanticSpanEntry::new(
                    SemanticSpanKind::Definition,
                    definition.name().to_string(),
                    definition.range(),
                    symbol,
                    Some(resolved_id),
                ));
                collect_definition_references(ctx, ir_id, definition, &mut entries);
            }

            for import in &module.imports {
                let identity = import_identity(ctx, ir_id, &import.symbol, &import.module);
                entries.push(SemanticSpanEntry::new(
                    SemanticSpanKind::Import,
                    import.symbol.clone(),
                    import.range,
                    identity.symbol,
                    identity.module,
                ));
            }

            Some((
                resolved_id,
                SemanticSpanIndex::build(module.source_id, entries),
            ))
        })
        .collect();

    for (module, index) in indexes {
        ctx.mib.module_mut(module).semantic_spans = index;
    }
}

fn collect_definition_references(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    definition: &ir::Definition,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    if let Some(oid) = definition.oid() {
        collect_oid_references(ctx, ir_mod, oid, true, entries);
    }

    match definition {
        ir::Definition::ObjectType(definition) => {
            collect_type_references(ctx, ir_mod, &definition.syntax, entries);
            collect_defval_references(ctx, ir_mod, definition.defval.as_ref(), entries);
        }
        ir::Definition::TypeDef(definition) => {
            collect_type_references(ctx, ir_mod, &definition.syntax, entries);
        }
        ir::Definition::ObjectGroup(definition) => {
            collect_name_refs_current(ctx, ir_mod, &definition.objects, entries);
        }
        ir::Definition::NotificationGroup(definition) => {
            collect_name_refs_current(ctx, ir_mod, &definition.notifications, entries);
        }
        ir::Definition::ModuleCompliance(definition) => {
            for module in &definition.modules {
                for object in &module.objects {
                    if let Some(syntax) = &object.syntax {
                        collect_type_references(ctx, ir_mod, syntax, entries);
                    }
                    if let Some(syntax) = &object.write_syntax {
                        collect_type_references(ctx, ir_mod, syntax, entries);
                    }
                }
            }
        }
        ir::Definition::AgentCapabilities(definition) => {
            for supports in &definition.supports {
                for reference in &supports.includes {
                    push_name_reference(
                        reference,
                        resolve_supports_identity(
                            ctx,
                            ir_mod,
                            &supports.module_name,
                            &reference.name,
                        ),
                        entries,
                    );
                }
                for variation in &supports.variations {
                    if let Some(syntax) = &variation.syntax {
                        collect_type_references(ctx, ir_mod, syntax, entries);
                    }
                    if let Some(syntax) = &variation.write_syntax {
                        collect_type_references(ctx, ir_mod, syntax, entries);
                    }
                    for reference in &variation.creation_requires {
                        push_name_reference(
                            reference,
                            resolve_supports_identity(
                                ctx,
                                ir_mod,
                                &supports.module_name,
                                &reference.name,
                            ),
                            entries,
                        );
                    }
                    collect_defval_references(ctx, ir_mod, variation.defval.as_ref(), entries);
                }
            }
        }
        ir::Definition::ModuleIdentity(_)
        | ir::Definition::ObjectIdentity(_)
        | ir::Definition::Notification(_)
        | ir::Definition::ValueAssignment(_) => {}
    }
}

fn collect_name_refs_current(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    references: &[ir::NameRef],
    entries: &mut Vec<SemanticSpanEntry>,
) {
    for reference in references {
        push_name_reference(
            reference,
            resolve_member_identity(ctx, ir_mod, &reference.name),
            entries,
        );
    }
}

fn push_name_reference(
    reference: &ir::NameRef,
    identity: Identity,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    entries.push(SemanticSpanEntry::new(
        SemanticSpanKind::SymbolReference,
        reference.name.clone(),
        reference.range,
        identity.symbol,
        identity.module,
    ));
}

fn collect_type_references(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    syntax: &ir::TypeSyntax,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    match syntax {
        ir::TypeSyntax::TypeRef { name, range } => {
            push_type_reference(ctx, ir_mod, name, *range, entries);
        }
        ir::TypeSyntax::IntegerEnum {
            base, base_range, ..
        } => {
            if let Some(range) = base_range {
                push_type_reference(ctx, ir_mod, base, *range, entries);
            }
        }
        ir::TypeSyntax::Constrained { base, .. } => {
            collect_type_references(ctx, ir_mod, base, entries);
        }
        ir::TypeSyntax::SequenceOf {
            entry_type,
            entry_type_range,
            ..
        } => {
            push_type_reference(ctx, ir_mod, entry_type, *entry_type_range, entries);
        }
        ir::TypeSyntax::Sequence { fields, .. } => {
            for field in fields {
                collect_type_references(ctx, ir_mod, &field.syntax, entries);
            }
        }
        ir::TypeSyntax::Bits { .. }
        | ir::TypeSyntax::OctetString { .. }
        | ir::TypeSyntax::ObjectIdentifier { .. } => {}
    }
}

fn push_type_reference(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
    range: SourceRange,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    let identity = ctx
        .lookup_type_for_module(ir_mod, name)
        .map(|(type_id, _)| {
            let symbol = Symbol::Type(type_id);
            Identity {
                symbol: Some(symbol),
                module: symbol.module(&ctx.mib),
            }
        })
        .unwrap_or_else(|| declared_scope_hint(ctx, ir_mod, name));
    entries.push(SemanticSpanEntry::new(
        SemanticSpanKind::TypeReference,
        name.to_string(),
        range,
        identity.symbol,
        identity.module,
    ));
}

fn collect_defval_references(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    defval: Option<&ir::DefVal>,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    if let Some(ir::DefVal::OidValue { components }) = defval {
        collect_oid_components(ctx, ir_mod, components, false, entries);
    }
}

fn collect_oid_references(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    oid: &ir::OidAssignment,
    allow_smi_fallback: bool,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    collect_oid_components(ctx, ir_mod, &oid.components, allow_smi_fallback, entries);
}

fn collect_oid_components(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    components: &[ir::OidComponent],
    allow_smi_fallback: bool,
    entries: &mut Vec<SemanticSpanEntry>,
) {
    for component in components {
        let (declared_name, range, identity) = match component {
            ir::OidComponent::Name { name, range } => (
                name.clone(),
                *range,
                resolve_oid_identity(ctx, ir_mod, name, allow_smi_fallback),
            ),
            ir::OidComponent::NamedNumber {
                name, name_range, ..
            } => (
                name.clone(),
                *name_range,
                resolve_oid_identity(ctx, ir_mod, name, allow_smi_fallback),
            ),
            ir::OidComponent::QualifiedName {
                module,
                name,
                range,
            } => (
                format!("{module}.{name}"),
                *range,
                resolve_qualified_node_identity(ctx, module, name),
            ),
            ir::OidComponent::QualifiedNamedNumber {
                module,
                name,
                name_range,
                ..
            } => (
                format!("{module}.{name}"),
                *name_range,
                resolve_qualified_node_identity(ctx, module, name),
            ),
            ir::OidComponent::Number { .. } => continue,
        };
        entries.push(SemanticSpanEntry::new(
            SemanticSpanKind::OidReference,
            declared_name,
            range,
            identity.symbol,
            identity.module,
        ));
    }
}

fn import_identity(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    symbol: &str,
    declared_module: &str,
) -> Identity {
    if let Some(&target) = ctx
        .module_imports
        .get(&ir_mod)
        .and_then(|imports| imports.get(symbol))
    {
        return exact_declared_identity(ctx, target, symbol);
    }
    module_name_hint(ctx, declared_module, symbol)
}

fn resolve_oid_identity(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    name: &str,
    allow_smi_fallback: bool,
) -> Identity {
    if matches!(name, "iso" | "ccitt" | "joint-iso-ccitt")
        && let Some(target) = ctx.snmpv2_smi
        && let Some(node) = declared_node_in_ir_module(ctx, target, name)
    {
        return exact_node_identity(ctx, target, name, node);
    }
    if let Some(node) = declared_node_in_ir_module(ctx, ir_mod, name) {
        return exact_node_identity(ctx, ir_mod, name, node);
    }
    if let Some(&target) = ctx
        .module_imports
        .get(&ir_mod)
        .and_then(|imports| imports.get(name))
        && let Some(node) = declared_node_in_ir_module(ctx, target, name)
    {
        return exact_node_identity(ctx, target, name, node);
    }
    if allow_smi_fallback && ctx.strictness.allow_constrained_fallbacks() {
        for target in [ctx.snmpv2_smi, ctx.rfc1155_smi].into_iter().flatten() {
            if ctx
                .module_oid_def_names
                .get(&target)
                .is_some_and(|names| names.contains(name))
                && let Some(node) = declared_node_in_ir_module(ctx, target, name)
            {
                return exact_node_identity(ctx, target, name, node);
            }
        }
    }
    declared_scope_hint(ctx, ir_mod, name)
}

fn resolve_qualified_node_identity(
    ctx: &ResolverContext,
    module_name: &str,
    name: &str,
) -> Identity {
    let Some(candidates) = ctx.module_index.get(module_name) else {
        return Identity::default();
    };
    for &target in candidates {
        if let Some(node) = declared_node_in_ir_module(ctx, target, name) {
            return exact_node_identity(ctx, target, name, node);
        }
    }
    candidates
        .first()
        .copied()
        .map(|target| exact_declared_identity(ctx, target, name))
        .unwrap_or_default()
}

fn resolve_member_identity(ctx: &ResolverContext, ir_mod: IrModuleId, name: &str) -> Identity {
    if let Some(node) = declared_node_in_ir_module(ctx, ir_mod, name) {
        return exact_node_identity(ctx, ir_mod, name, node);
    }
    if let Some(&target) = ctx
        .module_imports
        .get(&ir_mod)
        .and_then(|imports| imports.get(name))
        && let Some(node) = declared_node_in_ir_module(ctx, target, name)
    {
        return exact_node_identity(ctx, target, name, node);
    }
    if ctx.strictness.allow_global_fallbacks() {
        for (target, _) in ctx.all_modules() {
            if let Some(node) = declared_node_in_ir_module(ctx, target, name) {
                return exact_node_identity(ctx, target, name, node);
            }
        }
    }
    declared_scope_hint(ctx, ir_mod, name)
}

fn resolve_supports_identity(
    ctx: &ResolverContext,
    ir_mod: IrModuleId,
    supports_module: &str,
    name: &str,
) -> Identity {
    if let Some(target) = ctx.lookup_conformance_node(ir_mod, supports_module, name) {
        return exact_node_identity(ctx, target.module, name, target.node);
    }
    if !supports_module.is_empty() {
        let hint = module_name_hint(ctx, supports_module, name);
        if hint.module.is_some() {
            return hint;
        }
    }
    declared_scope_hint(ctx, ir_mod, name)
}

fn declared_scope_hint(ctx: &ResolverContext, ir_mod: IrModuleId, name: &str) -> Identity {
    if ctx
        .module_def_names
        .get(&ir_mod)
        .is_some_and(|names| names.contains(name))
    {
        return exact_declared_identity(ctx, ir_mod, name);
    }
    if let Some(&target) = ctx
        .module_imports
        .get(&ir_mod)
        .and_then(|imports| imports.get(name))
    {
        return exact_declared_identity(ctx, target, name);
    }
    if let Some(import) = ctx.modules[ir_mod.index()]
        .imports
        .iter()
        .find(|import| import.symbol == name)
    {
        return module_name_hint(ctx, &import.module, name);
    }
    Identity::default()
}

fn module_name_hint(ctx: &ResolverContext, module_name: &str, name: &str) -> Identity {
    ctx.module_index
        .get(module_name)
        .and_then(|candidates| candidates.first())
        .copied()
        .map(|target| exact_declared_identity(ctx, target, name))
        .unwrap_or_default()
}

fn exact_declared_identity(ctx: &ResolverContext, target: IrModuleId, name: &str) -> Identity {
    let module = ctx.module_to_resolved.get(&target).copied();
    let symbol = module.and_then(|module| ctx.mib.module_data(module).symbol(name));
    Identity { symbol, module }
}

fn exact_node_identity(
    ctx: &ResolverContext,
    target: IrModuleId,
    name: &str,
    node: NodeId,
) -> Identity {
    let module = ctx.module_to_resolved.get(&target).copied();
    let symbol = module.and_then(|module| {
        let data = ctx.mib.module_data(module);
        data.object_by_name(name)
            .filter(|id| ctx.mib.raw().object(*id).node() == Some(node))
            .map(Symbol::Object)
            .or_else(|| {
                data.notification_by_name(name)
                    .filter(|id| ctx.mib.raw().notification(*id).node() == Some(node))
                    .map(Symbol::Notification)
            })
            .or_else(|| {
                data.group_by_name(name)
                    .filter(|id| ctx.mib.raw().group(*id).node() == Some(node))
                    .map(Symbol::Group)
            })
            .or_else(|| {
                data.compliance_by_name(name)
                    .filter(|id| ctx.mib.raw().compliance(*id).node() == Some(node))
                    .map(Symbol::Compliance)
            })
            .or_else(|| {
                data.capability_by_name(name)
                    .filter(|id| ctx.mib.raw().capability(*id).node() == Some(node))
                    .map(Symbol::Capability)
            })
            .or_else(|| (data.node_by_name(name) == Some(node)).then_some(Symbol::Node(node)))
    });
    Identity { symbol, module }
}

fn declared_node_in_ir_module(
    ctx: &ResolverContext,
    target: IrModuleId,
    name: &str,
) -> Option<NodeId> {
    let node = ctx
        .module_symbol_to_node
        .get(&target)
        .and_then(|symbols| symbols.get(name))
        .copied()?;
    let module = ctx.module_to_resolved.get(&target).copied()?;
    ctx.mib
        .module_data(module)
        .node_by_name(name)
        .is_some_and(|declared| declared == node)
        .then_some(node)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::source::{ByteOffset, SourceOrigin, SourceSet};
    use crate::types::{DiagnosticConfig, ResolverStrictness};

    #[test]
    fn qualified_lookup_uses_the_same_available_module_version_as_oid_resolution() {
        let inputs: [(&str, &[u8]); 3] = [
            (
                "first",
                br#"DUPLICATE-MIB DEFINITIONS ::= BEGIN
shared OBJECT IDENTIFIER ::= { iso(1) 3 6 1 }
END
"#,
            ),
            (
                "second",
                br#"DUPLICATE-MIB DEFINITIONS ::= BEGIN
shared OBJECT IDENTIFIER ::= { iso(1) 3 6 2 }
END
"#,
            ),
            (
                "consumer",
                br#"VERSION-CONSUMER-MIB DEFINITIONS ::= BEGIN
consumer OBJECT IDENTIFIER ::= { DUPLICATE-MIB.shared 9 }
END
"#,
            ),
        ];
        let mut sources = SourceSet::new();
        let ids: Vec<_> = inputs
            .iter()
            .map(|(label, bytes)| {
                sources
                    .insert(SourceOrigin::memory(*label), *label, Arc::from(*bytes))
                    .unwrap()
            })
            .collect();
        let config = DiagnosticConfig::silent();
        let modules: Vec<_> = ids
            .iter()
            .flat_map(|id| {
                let document = sources.get(*id).unwrap();
                crate::parser::parse(document, &config)
                    .into_iter()
                    .map(|module| crate::lower::lower(module, document, &config))
                    .collect::<Vec<_>>()
            })
            .collect();

        let mib = super::super::resolve(modules, sources, ResolverStrictness::Strict, &config);
        let versions: Vec<_> = mib
            .modules()
            .filter(|module| module.name() == "DUPLICATE-MIB")
            .collect();
        assert_eq!(versions.len(), 2);
        let consumer = mib.module("VERSION-CONSUMER-MIB").unwrap();
        let source = consumer.source().unwrap();
        let start = source
            .bytes()
            .windows(b"DUPLICATE-MIB.shared".len())
            .position(|window| window == b"DUPLICATE-MIB.shared")
            .unwrap();
        let span = consumer
            .semantic_at(ByteOffset::try_from(start).unwrap())
            .unwrap();
        let resolved_parent = mib
            .node("consumer")
            .unwrap()
            .parent()
            .and_then(|node| node.module())
            .unwrap();
        assert_eq!(span.module, Some(resolved_parent.id()));
        let selected = versions
            .iter()
            .find(|module| module.id() == resolved_parent.id())
            .unwrap();
        assert_eq!(span.symbol, selected.data().symbol("shared"));
    }
}
