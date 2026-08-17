//! Phase 1: Module registration.
//!
//! Registers parsed modules in the [`ResolverContext`] and builds per-module
//! caches used by later phases. The loading pipeline supplies the SMI
//! foundation modules from configured sources or its embedded fallback.

use std::collections::HashSet;

use super::super::module::ModuleData;
use super::super::types::*;
use super::context::{IrModuleId, ResolverContext};
use crate::ir;
use crate::lower::base_modules;

/// Phase 1: Register all modules, create resolved module shells,
/// and build definition name indexes.
///
/// Stores the input module list in [`ResolverContext::modules`], extracts
/// MODULE-IDENTITY metadata, forwards parse/lowering diagnostics, caches
/// well-known foundation module ids, and populates per-module definition indexes.
pub(super) fn register_modules(ctx: &mut ResolverContext, input_modules: Vec<ir::Module>) {
    ctx.modules = input_modules;

    // Register each module.
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let m = &ctx.modules[idx];

        let mut resolved = ModuleData::new(m.name.clone());
        resolved.language = m.language;
        resolved.source_id = m.source_id;
        resolved.is_base = base_modules::is_base_module(&m.name);

        // Extract MODULE-IDENTITY metadata.
        for def in &m.definitions {
            if let ir::Definition::ModuleIdentity(mi) = def {
                resolved.last_updated = mi.last_updated.clone();
                resolved.organization = mi.organization.clone();
                resolved.contact_info = mi.contact_info.clone();
                resolved.description = mi.description.clone();
                resolved.revisions = mi
                    .revisions
                    .iter()
                    .map(|r| Revision {
                        date: r.date.clone(),
                        description: r.description.clone(),
                        range: r.range,
                    })
                    .collect();
                break;
            }
        }

        let resolved_id = ctx.mib.add_module(resolved);
        ctx.module_to_resolved.insert(ir_id, resolved_id);
        ctx.resolved_to_module.insert(resolved_id, ir_id);

        // Collect parse/lowering diagnostics.
        for diag in &m.diagnostics {
            ctx.mib.add_diagnostic(diag.clone());
        }

        // Cache base module references.
        match m.name.as_str() {
            "SNMPv2-SMI" => ctx.snmpv2_smi = Some(ir_id),
            "RFC1155-SMI" => ctx.rfc1155_smi = Some(ir_id),
            "SNMPv2-TC" => ctx.snmpv2_tc = Some(ir_id),
            _ => {}
        }

        // Add to module_index (supports multiple versions per name).
        ctx.module_index
            .entry(m.name.clone())
            .or_default()
            .push(ir_id);

        // Build definition name sets.
        let mut def_names = HashSet::new();
        let mut oid_def_names = HashSet::new();
        for def in &m.definitions {
            let name = def.name().to_string();
            if !name.is_empty() {
                def_names.insert(name.clone());
                if def.oid().is_some() {
                    oid_def_names.insert(name);
                }
            }
        }
        ctx.module_def_names.insert(ir_id, def_names);
        ctx.module_oid_def_names.insert(ir_id, oid_def_names);
    }
}

/// Group flat per-symbol imports into by-module form for a resolved module.
///
/// Converts the IR's flat list of `(symbol, module)` pairs into grouped
/// [`Import`] values sorted by first-appearance order of the source module,
/// with symbols sorted alphabetically within each group.
pub(super) fn group_imports(ir_mod: &ir::Module) -> Vec<Import> {
    use std::collections::HashMap;

    let mut order: Vec<&str> = Vec::new();
    let mut by_module: HashMap<&str, Vec<ImportSymbol>> = HashMap::new();
    for imp in &ir_mod.imports {
        match by_module.entry(&imp.module) {
            std::collections::hash_map::Entry::Vacant(e) => {
                order.push(imp.module.as_str());
                e.insert(vec![ImportSymbol {
                    name: imp.symbol.clone(),
                    range: imp.range,
                }]);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().push(ImportSymbol {
                    name: imp.symbol.clone(),
                    range: imp.range,
                });
            }
        }
    }

    order
        .into_iter()
        .filter_map(|module| by_module.remove(module).map(|symbols| (module, symbols)))
        .map(|(module, mut symbols)| {
            symbols.sort_by(|a, b| a.name.cmp(&b.name));
            Import {
                module: module.to_string(),
                symbols,
            }
        })
        .collect()
}
