//! Phase 2: Import resolution.
//!
//! Resolves cross-module symbol references declared in IMPORTS clauses.
//! Uses a multi-strategy approach:
//!
//! - **Direct** - symbol found in the named source module.
//! - **Alias** - source module name maps to a known alternate (e.g., SNMPv2-SMI-v1 -> SNMPv2-SMI).
//! - **Forwarding** - source module re-exports the symbol from a third module.
//! - **Partial** - resolves as many symbols as possible from a mixed group, reporting the rest.
//!
//! After initial resolution, [`resolve_transitive_imports`] collapses
//! multi-hop import chains so every import points directly at the defining
//! module. Post-resolution checks ([`check_unused_imports`],
//! [`check_obsolete_imports`]) detect unused and obsolete imports.

use std::collections::{HashMap, HashSet};

use tracing::trace;

use crate::source::SourceRange;
use crate::types::{DiagCode, Language};

use super::context::{IrModuleId, ResolverContext, UnresolvedReason};
use super::registration::group_imports;

/// Well-known macro names that are syntactic constructs, not resolvable symbols.
///
/// These appear in IMPORTS clauses but are SMI macro keywords, not actual
/// definitions that can be looked up. They are silently skipped during
/// import resolution.
const MACRO_NAMES: &[&str] = &[
    "MODULE-IDENTITY",
    "OBJECT-TYPE",
    "NOTIFICATION-TYPE",
    "TEXTUAL-CONVENTION",
    "OBJECT-GROUP",
    "NOTIFICATION-GROUP",
    "MODULE-COMPLIANCE",
    "AGENT-CAPABILITIES",
    "TRAP-TYPE",
    "OBJECT-IDENTITY",
];

fn is_macro_symbol(name: &str) -> bool {
    MACRO_NAMES.contains(&name)
}

/// Phase 2: Resolve imports for each module.
///
/// Iterates all modules and resolves each IMPORTS clause using the
/// multi-strategy approach described in the module docs. Populates
/// [`ResolverContext::module_imports`] with symbol-to-source mappings.
pub(super) fn resolve_imports(ctx: &mut ResolverContext) {
    let module_count = ctx.modules.len();
    for idx in 0..module_count {
        let ir_id = IrModuleId(idx as u32);
        resolve_imports_for_module(ctx, ir_id);
    }
}

fn resolve_imports_for_module(ctx: &mut ResolverContext, ir_mod: IrModuleId) {
    let m = &ctx.modules[ir_mod.index()];
    let importing_module = m.name.clone();
    if m.imports.is_empty() {
        return;
    }

    // Group imports by source module, preserving the order in which source
    // modules first appear. Symbols that appear in multiple groups (e.g.,
    // DisplayString imported from both RFC1213-MIB and SNMPv2-TC) are kept
    // only in the first group, so that iteration order is deterministic and
    // matches the MIB's import ordering.
    struct DuplicateImport {
        symbol: String,
        first_module: String,
        second_module: String,
        range: SourceRange,
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_module: HashMap<String, Vec<(String, SourceRange)>> = HashMap::new();
    let mut seen_symbols: HashMap<String, String> = HashMap::new(); // symbol -> first module
    let mut duplicates: Vec<DuplicateImport> = Vec::new();
    for imp in &m.imports {
        if let Some(first_mod) = seen_symbols.get(&imp.symbol) {
            if *first_mod != imp.module {
                duplicates.push(DuplicateImport {
                    symbol: imp.symbol.clone(),
                    first_module: first_mod.clone(),
                    second_module: imp.module.clone(),
                    range: imp.range,
                });
            }
            continue;
        }
        seen_symbols.insert(imp.symbol.clone(), imp.module.clone());
        match by_module.entry(imp.module.clone()) {
            std::collections::hash_map::Entry::Vacant(e) => {
                order.push(imp.module.clone());
                e.insert(vec![(imp.symbol.clone(), imp.range)]);
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().push((imp.symbol.clone(), imp.range));
            }
        }
    }
    for dup in duplicates {
        ctx.emit_diagnostic(
            DiagCode::ImportDuplicate,
            Some(ir_mod),
            Some(dup.range),
            format!(
                "duplicate import: {:?} already imported from {:?}, ignoring import from {:?}",
                dup.symbol, dup.first_module, dup.second_module,
            ),
        );
    }

    for from_module in &order {
        let symbols = by_module.get(from_module).unwrap();
        // Filter out MACRO symbols.
        let non_macro: Vec<&(String, SourceRange)> = symbols
            .iter()
            .filter(|(name, _)| !is_macro_symbol(name))
            .collect();

        if non_macro.is_empty() {
            continue;
        }

        // Try direct resolution.
        let candidates = ctx
            .module_index
            .get(from_module)
            .cloned()
            .unwrap_or_default();

        if let Some(source_id) = find_candidate_with_all_symbols(ctx, &candidates, &non_macro) {
            trace!(
                target: "mib_rs::resolver",
                component = "resolver",
                phase = "imports",
                module = %importing_module,
                source_module = %from_module,
                symbol_count = non_macro.len(),
                resolution = "direct",
                "resolved import group",
            );
            // All symbols found in this candidate.
            for (name, _) in &non_macro {
                ctx.module_imports
                    .entry(ir_mod)
                    .or_default()
                    .insert(name.to_string(), source_id);
            }
            continue;
        }

        // Fallback chain (constrained, Normal+).
        if ctx.strictness.allow_constrained_fallbacks()
            && let Some(alias) = base_module_import_alias(from_module)
        {
            let alias_candidates = ctx.module_index.get(alias).cloned().unwrap_or_default();
            if let Some(source_id) =
                find_candidate_with_all_symbols(ctx, &alias_candidates, &non_macro)
            {
                trace!(
                    target: "mib_rs::resolver",
                    component = "resolver",
                    phase = "imports",
                    module = %importing_module,
                    source_module = %from_module,
                    alias_module = %alias,
                    symbol_count = non_macro.len(),
                    resolution = "alias",
                    "resolved import group via alias",
                );
                for (name, _) in &non_macro {
                    ctx.module_imports
                        .entry(ir_mod)
                        .or_default()
                        .insert(name.to_string(), source_id);
                }
                continue;
            }
        }

        // Deterministic: explicit import forwarding remains enabled at every
        // strictness level.
        if try_import_forwarding(ctx, ir_mod, &candidates, &non_macro) {
            trace!(
                target: "mib_rs::resolver",
                component = "resolver",
                phase = "imports",
                module = %importing_module,
                source_module = %from_module,
                symbol_count = non_macro.len(),
                resolution = "forwarded",
                "resolved import group via forwarding",
            );
            continue;
        }

        // Deterministic per symbol: keep valid symbols from a mixed import
        // group even when some peers are missing.
        if !candidates.is_empty() {
            let resolved_symbol_count =
                count_directly_resolved_symbols(ctx, &non_macro, &candidates);
            let unresolved_symbol_count = non_macro.len().saturating_sub(resolved_symbol_count);
            trace!(
                target: "mib_rs::resolver",
                component = "resolver",
                phase = "imports",
                module = %importing_module,
                source_module = %from_module,
                symbol_count = non_macro.len(),
                resolved_symbol_count = resolved_symbol_count,
                unresolved_symbol_count = unresolved_symbol_count,
                resolution = "partial",
                "partially resolved import group",
            );
            try_partial_resolution(
                ctx,
                ir_mod,
                &importing_module,
                from_module,
                &candidates,
                &non_macro,
            );
            continue;
        }

        // All fallbacks exhausted - report all symbols as unresolved.
        trace!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "imports",
            module = %importing_module,
            source_module = %from_module,
            symbol_count = non_macro.len(),
            reason = UnresolvedReason::ModuleNotFound.as_str(),
            resolution = "unresolved",
            "failed to resolve import group",
        );
        for (name, range) in &non_macro {
            ctx.record_unresolved_import(
                name,
                &importing_module,
                from_module,
                UnresolvedReason::ModuleNotFound,
                ir_mod,
                Some(*range),
            );
        }
    }
}

fn count_directly_resolved_symbols(
    ctx: &ResolverContext,
    symbols: &[&(String, SourceRange)],
    candidates: &[IrModuleId],
) -> usize {
    symbols
        .iter()
        .filter(|(name, _)| resolve_imported_symbol(ctx, candidates, name).is_some())
        .count()
}

fn find_candidate_with_all_symbols(
    ctx: &ResolverContext,
    candidates: &[IrModuleId],
    symbols: &[&(String, SourceRange)],
) -> Option<IrModuleId> {
    if candidates.is_empty() {
        return None;
    }
    let total = symbols.len();

    struct Scored {
        mod_id: IrModuleId,
        symbol_count: usize,
        last_updated: String,
    }

    let mut scored: Vec<Scored> = candidates
        .iter()
        .filter_map(|&cand| {
            let def_names = ctx.module_def_names.get(&cand)?;
            let count = symbols
                .iter()
                .filter(|(name, _)| def_names.contains(name.as_str()))
                .count();
            Some(Scored {
                mod_id: cand,
                symbol_count: count,
                last_updated: normalize_timestamp(&ctx.extract_last_updated(cand)),
            })
        })
        .collect();

    scored.sort_by(|a, b| {
        b.symbol_count
            .cmp(&a.symbol_count)
            .then_with(|| b.last_updated.cmp(&a.last_updated))
    });

    scored
        .first()
        .filter(|s| s.symbol_count == total)
        .map(|s| s.mod_id)
}

use super::util::normalize_timestamp;

fn base_module_import_alias(name: &str) -> Option<&'static str> {
    match name {
        "SNMPv2-SMI-v1" => Some("SNMPv2-SMI"),
        "SNMPv2-TC-v1" => Some("SNMPv2-TC"),
        "RFC1315-MIB" => Some("FRAME-RELAY-DTE-MIB"),
        "RFC-1213" => Some("RFC1213-MIB"),
        _ => None,
    }
}

/// Try to resolve symbols through import forwarding.
fn try_import_forwarding(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    candidates: &[IrModuleId],
    symbols: &[&(String, SourceRange)],
) -> bool {
    for &cand in candidates {
        let mut forwarded: Vec<(String, IrModuleId)> = Vec::new();

        for (name, _) in symbols {
            let mut visited = HashSet::new();
            let Some(source) = resolve_imported_symbol_from_module(ctx, cand, name, &mut visited)
            else {
                break;
            };
            forwarded.push((name.to_string(), source));
        }

        if forwarded.len() == symbols.len() {
            for (name, target) in forwarded {
                ctx.module_imports
                    .entry(ir_mod)
                    .or_default()
                    .insert(name, target);
            }
            return true;
        }
    }
    false
}

fn candidate_import_source_module<'a>(
    ctx: &'a ResolverContext,
    candidate: IrModuleId,
    symbol: &str,
) -> Option<&'a str> {
    let m = &ctx.modules[candidate.index()];
    m.imports
        .iter()
        .find(|imp| imp.symbol == symbol)
        .map(|imp| imp.module.as_str())
}

fn resolve_imported_symbol_from_module(
    ctx: &ResolverContext,
    candidate: IrModuleId,
    symbol: &str,
    visited: &mut HashSet<IrModuleId>,
) -> Option<IrModuleId> {
    if ctx
        .module_def_names
        .get(&candidate)
        .is_some_and(|defs| defs.contains(symbol))
    {
        return Some(candidate);
    }
    if !visited.insert(candidate) {
        return None;
    }

    let result = candidate_import_source_module(ctx, candidate, symbol).and_then(|source_name| {
        let source_candidates = ctx
            .module_index
            .get(source_name)
            .cloned()
            .unwrap_or_default();
        resolve_imported_symbol_with_visited(ctx, &source_candidates, symbol, visited)
    });
    visited.remove(&candidate);
    result
}

fn resolve_imported_symbol_with_visited(
    ctx: &ResolverContext,
    candidates: &[IrModuleId],
    symbol: &str,
    visited: &mut HashSet<IrModuleId>,
) -> Option<IrModuleId> {
    let mut ordered: Vec<(IrModuleId, String)> = candidates
        .iter()
        .copied()
        .map(|id| (id, normalize_timestamp(&ctx.extract_last_updated(id))))
        .collect();
    ordered.sort_by(|a, b| b.1.cmp(&a.1));

    ordered.into_iter().find_map(|(candidate, _)| {
        resolve_imported_symbol_from_module(ctx, candidate, symbol, visited)
    })
}

/// Resolve symbols individually against candidates.
fn try_partial_resolution(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    importing_module: &str,
    from_module: &str,
    candidates: &[IrModuleId],
    symbols: &[&(String, SourceRange)],
) {
    for (name, range) in symbols {
        if let Some(source) = resolve_imported_symbol(ctx, candidates, name) {
            ctx.module_imports
                .entry(ir_mod)
                .or_default()
                .insert(name.to_string(), source);
        } else {
            ctx.record_unresolved_import(
                name,
                importing_module,
                from_module,
                UnresolvedReason::SymbolNotExported,
                ir_mod,
                Some(*range),
            );
        }
    }
}

fn resolve_imported_symbol(
    ctx: &ResolverContext,
    candidates: &[IrModuleId],
    symbol: &str,
) -> Option<IrModuleId> {
    for &candidate in candidates {
        let mut visited = HashSet::new();
        if let Some(source) =
            resolve_imported_symbol_from_module(ctx, candidate, symbol, &mut visited)
        {
            return Some(source);
        }
    }

    None
}

/// Collapse multi-hop import chains to point directly at the defining module.
///
/// After initial import resolution, A may import symbol X from B, which
/// itself imports X from C. This pass rewrites the mapping so A's import
/// of X points directly at C, eliminating the intermediate hop.
pub(super) fn resolve_transitive_imports(ctx: &mut ResolverContext) {
    let mut resolutions = Vec::new();
    for (&mod_id, imports) in &ctx.module_imports {
        for (symbol, &start) in imports {
            resolutions.push((
                mod_id,
                symbol.clone(),
                start,
                resolve_ultimate_definer(ctx, start, symbol),
            ));
        }
    }

    for (mod_id, symbol, start, definer) in resolutions {
        if let Some(definer) = definer {
            if definer != start
                && let Some(imports) = ctx.module_imports.get_mut(&mod_id)
            {
                imports.insert(symbol, definer);
            }
            continue;
        }

        if let Some(imports) = ctx.module_imports.get_mut(&mod_id) {
            imports.remove(&symbol);
        }
        let (from_module, range) = original_import(ctx, mod_id, &symbol, start);
        let importing_module = ctx.modules[mod_id.index()].name.clone();
        ctx.record_unresolved_import(
            symbol,
            importing_module,
            from_module,
            UnresolvedReason::SymbolNotExported,
            mod_id,
            range,
        );
    }
}

fn original_import(
    ctx: &ResolverContext,
    importing_module: IrModuleId,
    symbol: &str,
    fallback: IrModuleId,
) -> (String, Option<SourceRange>) {
    ctx.modules[importing_module.index()]
        .imports
        .iter()
        .find(|imp| imp.symbol == symbol)
        .map(|imp| (imp.module.clone(), Some(imp.range)))
        .unwrap_or_else(|| (ctx.modules[fallback.index()].name.clone(), None))
}

fn resolve_ultimate_definer(
    ctx: &ResolverContext,
    start: IrModuleId,
    symbol: &str,
) -> Option<IrModuleId> {
    let mut visited = HashSet::new();
    let mut current = start;
    loop {
        if !visited.insert(current) {
            return None; // cycle - chain is broken
        }
        if let Some(defs) = ctx.module_def_names.get(&current)
            && defs.contains(symbol)
        {
            return Some(current);
        }
        if let Some(next) = ctx
            .module_imports
            .get(&current)
            .and_then(|imps| imps.get(symbol))
        {
            current = *next;
            continue;
        }
        return None; // dead end - symbol not defined here and no further chain
    }
}

/// Post-resolution: warn about imported symbols never used during resolution.
pub(super) fn check_unused_imports(ctx: &mut ResolverContext) {
    let mut diagnostics = Vec::new();

    for (ir_id, m) in ctx.all_modules() {
        if m.imports.is_empty() || crate::lower::base_modules::is_base_module(&m.name) {
            continue;
        }

        let used = ctx.used_imports.get(&ir_id);
        let resolved_imports = ctx.module_imports.get(&ir_id);

        for imp in &m.imports {
            if is_macro_symbol(&imp.symbol) {
                continue;
            }
            // Skip imports that failed to resolve (already reported).
            let did_resolve = resolved_imports.is_some_and(|imps| imps.contains_key(&imp.symbol));
            if !did_resolve {
                continue;
            }
            let is_used = used.is_some_and(|u| u.contains(&imp.symbol));
            if !is_used {
                diagnostics.push((
                    ir_id,
                    imp.range,
                    format!("unused import: {} from {}", imp.symbol, imp.module),
                ));
            }
        }
    }

    for (ir_id, range, message) in diagnostics {
        ctx.emit_diagnostic(DiagCode::ImportUnused, Some(ir_id), Some(range), message);
    }
}

/// Post-resolution: warn about importing from obsolete SMIv1 modules.
pub(super) fn check_obsolete_imports(ctx: &mut ResolverContext) {
    let mut diagnostics = Vec::new();

    for (ir_id, m) in ctx.all_modules() {
        if m.language != Language::SMIv2 {
            continue;
        }

        for imp in &m.imports {
            let replacement = match (imp.module.as_str(), imp.symbol.as_str()) {
                ("RFC1155-SMI", _) | ("RFC1065-SMI", _) => Some("SNMPv2-SMI"),
                ("RFC1213-MIB", "mib-2") => Some("SNMPv2-SMI"),
                ("RFC1213-MIB", "DisplayString") => Some("SNMPv2-TC"),
                _ => None,
            };

            if let Some(repl) = replacement {
                diagnostics.push((
                    ir_id,
                    imp.range,
                    format!(
                        "obsolete import: {} from {} (use {} instead)",
                        imp.symbol, imp.module, repl
                    ),
                ));
            }
        }
    }

    for (ir_id, range, message) in diagnostics {
        ctx.emit_diagnostic(DiagCode::ObsoleteImport, Some(ir_id), Some(range), message);
    }
}

/// Copy grouped imports and used-import tracking to resolved modules.
///
/// Populates each resolved module's [`imports`](super::super::module::ModuleData::imports)
/// and [`used_import_names`](super::super::module::ModuleData::used_import_names) fields.
pub(super) fn copy_used_imports_to_modules(ctx: &mut ResolverContext) {
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let resolved_id = match ctx.module_to_resolved.get(&ir_id) {
            Some(&id) => id,
            None => continue,
        };

        let ir_mod = &ctx.modules[ir_id.index()];
        let grouped = group_imports(ir_mod);

        let used = ctx.used_imports.get(&ir_id);
        let resolved_mod = ctx.mib.module_mut(resolved_id);
        resolved_mod.imports = grouped;

        if let Some(used_set) = used {
            resolved_mod.used_import_names = used_set.clone();
        }
    }
}

/// Copy resolved import mappings (symbol -> source [`ModuleId`]) to resolved modules.
///
/// Populates each resolved module's
/// [`resolved_imports`](super::super::module::ModuleData::resolved_imports) field.
pub(super) fn copy_resolved_imports_to_modules(ctx: &mut ResolverContext) {
    for idx in 0..ctx.modules.len() {
        let ir_id = IrModuleId(idx as u32);
        let resolved_id = match ctx.module_to_resolved.get(&ir_id) {
            Some(&id) => id,
            None => continue,
        };

        if let Some(imports) = ctx.module_imports.get(&ir_id) {
            let mut resolved_map = HashMap::new();
            for (symbol, &source_ir) in imports {
                if let Some(&source_resolved) = ctx.module_to_resolved.get(&source_ir) {
                    resolved_map.insert(symbol.clone(), source_resolved);
                }
            }
            ctx.mib.module_mut(resolved_id).resolved_imports = resolved_map;
        }
    }
}
