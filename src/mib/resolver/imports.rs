use std::collections::{HashMap, HashSet};

use tracing::trace;

use crate::types::{DiagCode, Language, Span};

use super::context::{IrModuleId, ResolverContext, UnresolvedReason};
use super::registration::group_imports;

/// Well-known macro names that are syntactic constructs, not resolvable symbols.
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
        span: Span,
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_module: HashMap<String, Vec<(String, Span)>> = HashMap::new();
    let mut seen_symbols: HashMap<String, String> = HashMap::new(); // symbol -> first module
    let mut duplicates: Vec<DuplicateImport> = Vec::new();
    for imp in &m.imports {
        if let Some(first_mod) = seen_symbols.get(&imp.symbol) {
            if *first_mod != imp.module {
                duplicates.push(DuplicateImport {
                    symbol: imp.symbol.clone(),
                    first_module: first_mod.clone(),
                    second_module: imp.module.clone(),
                    span: imp.span,
                });
            }
            continue;
        }
        seen_symbols.insert(imp.symbol.clone(), imp.module.clone());
        if !by_module.contains_key(&imp.module) {
            order.push(imp.module.clone());
        }
        by_module
            .entry(imp.module.clone())
            .or_default()
            .push((imp.symbol.clone(), imp.span));
    }
    for dup in duplicates {
        ctx.emit_diagnostic(
            DiagCode::ImportDuplicate,
            Some(ir_mod),
            dup.span,
            format!(
                "duplicate import: {:?} already imported from {:?}, ignoring import from {:?}",
                dup.symbol, dup.first_module, dup.second_module,
            ),
        );
    }

    for from_module in &order {
        let symbols = by_module.get(from_module).unwrap();
        // Filter out MACRO symbols.
        let non_macro: Vec<&(String, Span)> = symbols
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
        for (name, span) in &non_macro {
            ctx.record_unresolved_import(
                name,
                &importing_module,
                from_module,
                UnresolvedReason::ModuleNotFound,
                ir_mod,
                *span,
            );
        }
    }
}

fn count_directly_resolved_symbols(
    ctx: &ResolverContext,
    symbols: &[&(String, Span)],
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
    symbols: &[&(String, Span)],
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
    symbols: &[&(String, Span)],
) -> bool {
    for &cand in candidates {
        let mut all_resolved = true;
        let mut forwarded: Vec<(String, IrModuleId)> = Vec::new();

        for (name, _) in symbols {
            // Check if the candidate defines it directly.
            if ctx
                .module_def_names
                .get(&cand)
                .is_some_and(|dn| dn.contains(name.as_str()))
            {
                forwarded.push((name.to_string(), cand));
                continue;
            }
            // Check if the candidate re-exports it via its own IMPORTS declarations.
            let source_mod = candidate_import_source_module(ctx, cand, name);
            if let Some(source_name) = source_mod {
                let source_candidates = ctx
                    .module_index
                    .get(source_name)
                    .cloned()
                    .unwrap_or_default();
                if let Some(fwd) = best_candidate(ctx, &source_candidates) {
                    forwarded.push((name.to_string(), fwd));
                } else {
                    all_resolved = false;
                    break;
                }
            } else {
                all_resolved = false;
                break;
            }
        }

        if all_resolved {
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

fn best_candidate(ctx: &ResolverContext, candidates: &[IrModuleId]) -> Option<IrModuleId> {
    // Pick the module with the newest LAST-UPDATED timestamp.
    // Falls back to the first candidate when no timestamps are present.
    let mut scored: Vec<(IrModuleId, String)> = candidates
        .iter()
        .copied()
        .map(|id| (id, normalize_timestamp(&ctx.extract_last_updated(id))))
        .collect();
    scored.sort_by(|a, b| b.1.cmp(&a.1));
    scored.first().map(|s| s.0)
}

/// Resolve symbols individually against candidates.
fn try_partial_resolution(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    importing_module: &str,
    from_module: &str,
    candidates: &[IrModuleId],
    symbols: &[&(String, Span)],
) {
    for (name, span) in symbols {
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
                *span,
            );
        }
    }
}

fn resolve_imported_symbol(
    ctx: &ResolverContext,
    candidates: &[IrModuleId],
    symbol: &str,
) -> Option<IrModuleId> {
    for &cand in candidates {
        if ctx
            .module_def_names
            .get(&cand)
            .is_some_and(|defs| defs.contains(symbol))
        {
            return Some(cand);
        }

        if let Some(source_name) = candidate_import_source_module(ctx, cand, symbol) {
            let source_candidates = ctx
                .module_index
                .get(source_name)
                .cloned()
                .unwrap_or_default();
            if let Some(source) = best_candidate(ctx, &source_candidates) {
                return Some(source);
            }
        }
    }

    None
}

/// Collapse multi-hop import chains to point directly at the defining module.
pub(super) fn resolve_transitive_imports(ctx: &mut ResolverContext) {
    let mod_ids: Vec<IrModuleId> = ctx.module_imports.keys().copied().collect();
    for mod_id in mod_ids {
        let symbols: Vec<String> = ctx
            .module_imports
            .get(&mod_id)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();

        for symbol in symbols {
            let start = match ctx.module_imports.get(&mod_id).and_then(|m| m.get(&symbol)) {
                Some(&s) => s,
                None => continue,
            };

            let definer = resolve_ultimate_definer(ctx, start, &symbol);
            if definer != start
                && let Some(imports) = ctx.module_imports.get_mut(&mod_id)
            {
                imports.insert(symbol, definer);
            }
        }
    }
}

fn resolve_ultimate_definer(ctx: &ResolverContext, start: IrModuleId, symbol: &str) -> IrModuleId {
    let mut visited = HashSet::new();
    let mut current = start;
    loop {
        if !visited.insert(current) {
            return current; // cycle
        }
        if let Some(defs) = ctx.module_def_names.get(&current)
            && defs.contains(symbol)
        {
            return current;
        }
        if let Some(next) = ctx
            .module_imports
            .get(&current)
            .and_then(|imps| imps.get(symbol))
        {
            current = *next;
            continue;
        }
        return current;
    }
}

/// Post-resolution: warn about imported symbols never used during resolution.
pub(super) fn check_unused_imports(ctx: &mut ResolverContext) {
    let mut diagnostics = Vec::new();

    for (ir_id, m) in ctx.all_modules() {
        if m.imports.is_empty() {
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
                    imp.span,
                    format!("unused import: {} from {}", imp.symbol, imp.module),
                ));
            }
        }
    }

    for (ir_id, span, message) in diagnostics {
        ctx.emit_diagnostic(DiagCode::ImportUnused, Some(ir_id), span, message);
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
                    imp.span,
                    format!(
                        "obsolete import: {} from {} (use {} instead)",
                        imp.symbol, imp.module, repl
                    ),
                ));
            }
        }
    }

    for (ir_id, span, message) in diagnostics {
        ctx.emit_diagnostic(DiagCode::ObsoleteImport, Some(ir_id), span, message);
    }
}

/// Copy used import information to resolved modules.
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

/// Copy resolved import mappings (symbol -> source module) to resolved modules.
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
