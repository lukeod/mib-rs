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

use super::super::types::{
    ImportAttemptOutcome, ImportResolution, ImportResolutionAttempt, ImportResolutionMode,
    ImportResolutionStage,
};

use super::context::{
    ImportAttemptInternal, ImportResolutionModeInternal, IrModuleId, ResolverContext,
    UnresolvedReason,
};
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

        let direct_source = find_candidate_with_all_symbols(
            ctx,
            ir_mod,
            &candidates,
            &non_macro,
            ImportResolutionStage::Direct,
        );
        if let Some(source_id) = direct_source {
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
                record_import_mode(ctx, ir_mod, name, ImportResolutionModeInternal::Direct);
                record_selected_path(ctx, ir_mod, name, vec![source_id]);
            }
            continue;
        }

        // Fallback chain (constrained, Normal+).
        if ctx.strictness.allow_constrained_fallbacks()
            && let Some(alias) = base_module_import_alias(from_module)
        {
            let alias_candidates = ctx.module_index.get(alias).cloned().unwrap_or_default();
            let alias_source = find_candidate_with_all_symbols(
                ctx,
                ir_mod,
                &alias_candidates,
                &non_macro,
                ImportResolutionStage::Alias,
            );
            if let Some(source_id) = alias_source {
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
                    record_import_mode(ctx, ir_mod, name, ImportResolutionModeInternal::Alias);
                    record_selected_path(ctx, ir_mod, name, vec![source_id]);
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
            let (resolved_symbol_count, unresolved_symbol_count) = try_partial_resolution(
                ctx,
                ir_mod,
                &importing_module,
                from_module,
                &candidates,
                &non_macro,
            );
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
            record_import_mode(ctx, ir_mod, name, ImportResolutionModeInternal::Unresolved);
            record_live_attempts(
                ctx,
                ir_mod,
                name,
                vec![ImportAttemptInternal {
                    stage: ImportResolutionStage::Unresolved,
                    path: Vec::new(),
                    missing_module: Some(from_module.clone()),
                    outcome: ImportAttemptOutcome::ModuleNotFound,
                    selected: false,
                }],
            );
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

fn find_candidate_with_all_symbols(
    ctx: &mut ResolverContext,
    module: IrModuleId,
    candidates: &[IrModuleId],
    symbols: &[&(String, SourceRange)],
    stage: ImportResolutionStage,
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

    let mut scored = Vec::new();
    for &candidate in candidates {
        let Some(definitions) = ctx.module_def_names.get(&candidate) else {
            continue;
        };
        let outcomes = symbols
            .iter()
            .map(|(symbol, _)| (symbol.as_str(), definitions.contains(symbol.as_str())))
            .collect::<Vec<_>>();
        let symbol_count = outcomes.iter().filter(|(_, resolved)| *resolved).count();
        let last_updated = normalize_timestamp(&ctx.extract_last_updated(candidate));
        for (symbol, resolved) in outcomes {
            record_live_attempts(
                ctx,
                module,
                symbol,
                vec![ImportAttemptInternal {
                    stage,
                    path: vec![candidate],
                    missing_module: None,
                    outcome: if resolved {
                        ImportAttemptOutcome::Resolved
                    } else {
                        ImportAttemptOutcome::SymbolNotDefined
                    },
                    selected: false,
                }],
            );
        }
        scored.push(Scored {
            mod_id: candidate,
            symbol_count,
            last_updated,
        });
    }

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
        let mut forwarded: Vec<(String, IrModuleId, Vec<IrModuleId>)> = Vec::new();

        for (name, _) in symbols {
            let traversal =
                traverse_import_candidate(ctx, cand, name, ImportResolutionStage::Forwarding);
            let resolved = traversal.resolved;
            record_live_attempts(ctx, ir_mod, name, traversal.attempts);
            let Some((source, path)) = resolved else {
                break;
            };
            forwarded.push((name.to_string(), source, path));
        }

        if forwarded.len() == symbols.len() {
            for (name, target, path) in forwarded {
                ctx.module_imports
                    .entry(ir_mod)
                    .or_default()
                    .insert(name.clone(), target);
                record_import_mode(ctx, ir_mod, &name, ImportResolutionModeInternal::Forwarded);
                record_selected_path(ctx, ir_mod, &name, path);
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

struct ImportTraversal {
    resolved: Option<(IrModuleId, Vec<IrModuleId>)>,
    attempts: Vec<ImportAttemptInternal>,
}

fn traverse_import_candidate(
    ctx: &ResolverContext,
    candidate: IrModuleId,
    symbol: &str,
    stage: ImportResolutionStage,
) -> ImportTraversal {
    let mut visited = HashSet::new();
    let mut path = Vec::new();
    let mut attempts = Vec::new();
    let resolved = explore_import_candidate(
        ctx,
        candidate,
        symbol,
        &mut visited,
        &mut path,
        &mut attempts,
        stage,
    );
    ImportTraversal { resolved, attempts }
}

fn ordered_import_candidates(ctx: &ResolverContext, candidates: &[IrModuleId]) -> Vec<IrModuleId> {
    let mut ordered: Vec<(IrModuleId, String)> = candidates
        .iter()
        .copied()
        .map(|id| (id, normalize_timestamp(&ctx.extract_last_updated(id))))
        .collect();
    ordered.sort_by(|a, b| b.1.cmp(&a.1));
    ordered
        .into_iter()
        .map(|(candidate, _)| candidate)
        .collect()
}

/// Resolve symbols individually against candidates.
fn try_partial_resolution(
    ctx: &mut ResolverContext,
    ir_mod: IrModuleId,
    importing_module: &str,
    from_module: &str,
    candidates: &[IrModuleId],
    symbols: &[&(String, SourceRange)],
) -> (usize, usize) {
    let mut resolved_count = 0;
    let mut unresolved_count = 0;
    for (name, range) in symbols {
        let (resolved, attempts) =
            resolve_imported_symbol(ctx, candidates, name, ImportResolutionStage::Partial);
        record_live_attempts(ctx, ir_mod, name, attempts);
        if let Some((source, path)) = resolved {
            ctx.module_imports
                .entry(ir_mod)
                .or_default()
                .insert(name.to_string(), source);
            record_import_mode(ctx, ir_mod, name, ImportResolutionModeInternal::Partial);
            record_selected_path(ctx, ir_mod, name, path);
            resolved_count += 1;
        } else {
            record_import_mode(ctx, ir_mod, name, ImportResolutionModeInternal::Partial);
            ctx.record_unresolved_import(
                name,
                importing_module,
                from_module,
                UnresolvedReason::SymbolNotExported,
                ir_mod,
                Some(*range),
            );
            unresolved_count += 1;
        }
    }
    (resolved_count, unresolved_count)
}

fn resolve_imported_symbol(
    ctx: &ResolverContext,
    candidates: &[IrModuleId],
    symbol: &str,
    stage: ImportResolutionStage,
) -> (
    Option<(IrModuleId, Vec<IrModuleId>)>,
    Vec<ImportAttemptInternal>,
) {
    let mut attempts = Vec::new();
    for &candidate in candidates {
        let traversal = traverse_import_candidate(ctx, candidate, symbol, stage);
        attempts.extend(traversal.attempts);
        if let Some(resolved) = traversal.resolved {
            return (Some(resolved), attempts);
        }
    }

    (None, attempts)
}

fn record_import_mode(
    ctx: &mut ResolverContext,
    module: IrModuleId,
    symbol: &str,
    mode: ImportResolutionModeInternal,
) {
    ctx.import_resolution_modes
        .entry(module)
        .or_default()
        .insert(symbol.to_owned(), mode);
}

fn record_live_attempts(
    ctx: &mut ResolverContext,
    module: IrModuleId,
    symbol: &str,
    attempts: Vec<ImportAttemptInternal>,
) {
    ctx.import_resolution_attempts
        .entry(module)
        .or_default()
        .entry(symbol.to_owned())
        .or_default()
        .extend(attempts);
}

fn record_selected_path(
    ctx: &mut ResolverContext,
    module: IrModuleId,
    symbol: &str,
    path: Vec<IrModuleId>,
) {
    if let Some(attempts) = ctx
        .import_resolution_attempts
        .get_mut(&module)
        .and_then(|symbols| symbols.get_mut(symbol))
        && let Some(attempt) = attempts.iter_mut().rev().find(|attempt| {
            !attempt.selected
                && attempt.outcome == ImportAttemptOutcome::Resolved
                && attempt.path == path
        })
    {
        attempt.selected = true;
    }
    ctx.import_selected_paths
        .entry(module)
        .or_default()
        .insert(symbol.to_owned(), path);
}

/// Retain exact import candidate attempts before the transitive map is collapsed.
pub(super) fn copy_import_provenance_to_modules(ctx: &mut ResolverContext) {
    let mut records = Vec::new();
    for (&module, modes) in &ctx.import_resolution_modes {
        for (symbol, &mode) in modes {
            let declared_module = candidate_import_source_module(ctx, module, symbol)
                .unwrap_or_default()
                .to_owned();
            let target = ctx
                .module_imports
                .get(&module)
                .and_then(|imports| imports.get(symbol))
                .copied();
            let attempts = ctx
                .import_resolution_attempts
                .get(&module)
                .and_then(|symbols| symbols.get(symbol))
                .cloned()
                .unwrap_or_default();
            let selected_path = ctx
                .import_selected_paths
                .get(&module)
                .and_then(|symbols| symbols.get(symbol))
                .cloned()
                .unwrap_or_default();

            let public_mode = match mode {
                ImportResolutionModeInternal::Direct => ImportResolutionMode::Direct,
                ImportResolutionModeInternal::Alias => ImportResolutionMode::Alias,
                ImportResolutionModeInternal::Forwarded => ImportResolutionMode::Forwarded,
                ImportResolutionModeInternal::Partial => ImportResolutionMode::Partial,
                ImportResolutionModeInternal::Unresolved => ImportResolutionMode::Unresolved,
            };
            let public_mode = if target.is_none()
                && attempts
                    .iter()
                    .any(|attempt| attempt.outcome == ImportAttemptOutcome::Cycle)
            {
                ImportResolutionMode::Cycle
            } else {
                public_mode
            };
            let resolved_module = ctx.module_to_resolved[&module];
            let target = target.and_then(|target| ctx.module_to_resolved.get(&target).copied());
            let selected_path = selected_path
                .into_iter()
                .filter_map(|module| ctx.module_to_resolved.get(&module).copied())
                .collect::<Vec<_>>();
            let attempts = attempts
                .into_iter()
                .map(|attempt| ImportResolutionAttempt {
                    stage: attempt.stage,
                    selected: attempt.selected,
                    path: attempt
                        .path
                        .into_iter()
                        .filter_map(|module| ctx.module_to_resolved.get(&module).copied())
                        .collect(),
                    missing_module: attempt.missing_module,
                    outcome: attempt.outcome,
                })
                .collect();
            records.push((
                resolved_module,
                symbol.clone(),
                ImportResolution {
                    symbol: symbol.clone(),
                    declared_module,
                    mode: public_mode,
                    target,
                    selected_path,
                    attempts,
                },
            ));
        }
    }

    for (module, symbol, resolution) in records {
        ctx.mib
            .module_mut(module)
            .import_resolutions
            .insert(symbol, resolution);
    }
}

fn explore_import_candidate(
    ctx: &ResolverContext,
    candidate: IrModuleId,
    symbol: &str,
    active: &mut HashSet<IrModuleId>,
    path: &mut Vec<IrModuleId>,
    attempts: &mut Vec<ImportAttemptInternal>,
    stage: ImportResolutionStage,
) -> Option<(IrModuleId, Vec<IrModuleId>)> {
    path.push(candidate);
    if ctx
        .module_def_names
        .get(&candidate)
        .is_some_and(|definitions| definitions.contains(symbol))
    {
        attempts.push(ImportAttemptInternal {
            stage,
            path: path.clone(),
            missing_module: None,
            outcome: ImportAttemptOutcome::Resolved,
            selected: false,
        });
        let resolved = Some((candidate, path.clone()));
        path.pop();
        return resolved;
    }
    if !active.insert(candidate) {
        attempts.push(ImportAttemptInternal {
            stage,
            path: path.clone(),
            missing_module: None,
            outcome: ImportAttemptOutcome::Cycle,
            selected: false,
        });
        path.pop();
        return None;
    }

    let result = match candidate_import_source_module(ctx, candidate, symbol) {
        Some(source_name) => {
            let source_candidates = ctx
                .module_index
                .get(source_name)
                .cloned()
                .unwrap_or_default();
            if source_candidates.is_empty() {
                attempts.push(ImportAttemptInternal {
                    stage,
                    path: path.clone(),
                    missing_module: Some(source_name.to_owned()),
                    outcome: ImportAttemptOutcome::ModuleNotFound,
                    selected: false,
                });
                None
            } else {
                ordered_import_candidates(ctx, &source_candidates)
                    .into_iter()
                    .find_map(|next| {
                        explore_import_candidate(ctx, next, symbol, active, path, attempts, stage)
                    })
            }
        }
        None => {
            attempts.push(ImportAttemptInternal {
                stage,
                path: path.clone(),
                missing_module: None,
                outcome: ImportAttemptOutcome::SymbolNotDefined,
                selected: false,
            });
            None
        }
    };
    active.remove(&candidate);
    path.pop();
    result
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
            let module = ctx.mib.module_mut(resolved_id);
            for (symbol, resolution) in &mut module.import_resolutions {
                resolution.target = resolved_map.get(symbol).copied();
            }
            module.resolved_imports = resolved_map;
        } else {
            let module = ctx.mib.module_mut(resolved_id);
            for resolution in module.import_resolutions.values_mut() {
                resolution.target = None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::mib::{ImportResolutionMode, ImportResolutionStage, ResolutionTraceError};
    use crate::source::{SourceOrigin, SourceSet};
    use crate::types::{DiagnosticConfig, ResolutionDomain, ResolverStrictness};

    fn resolve_sources(inputs: &[(&str, &[u8])]) -> crate::Mib {
        let mut sources = SourceSet::new();
        let source_ids = inputs
            .iter()
            .map(|(label, bytes)| {
                sources
                    .insert(SourceOrigin::memory(*label), *label, Arc::from(*bytes))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let config = DiagnosticConfig::silent();
        let modules = source_ids
            .iter()
            .flat_map(|source_id| {
                let document = sources.get(*source_id).unwrap();
                crate::parser::parse(document, &config)
                    .into_iter()
                    .map(|module| crate::lower::lower(module, document, &config))
                    .collect::<Vec<_>>()
            })
            .collect();
        super::super::resolve(modules, sources, ResolverStrictness::Normal, &config)
    }

    #[test]
    fn forwarding_provenance_retains_selected_duplicate_module_version() {
        let mib = resolve_sources(&[
            (
                "old-version",
                br#"TRACE-VERSION-MIB DEFINITIONS ::= BEGIN
versionIdentity MODULE-IDENTITY
    LAST-UPDATED "200001010000Z"
    ORGANIZATION "Old"
    CONTACT-INFO "Old"
    DESCRIPTION "Old."
    ::= { iso 424280 }
versionSymbol OBJECT IDENTIFIER ::= { versionIdentity 1 }
END
"#,
            ),
            (
                "new-version",
                br#"TRACE-VERSION-MIB DEFINITIONS ::= BEGIN
versionIdentity MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "New"
    CONTACT-INFO "New"
    DESCRIPTION "New."
    ::= { iso 424281 }
versionSymbol OBJECT IDENTIFIER ::= { versionIdentity 1 }
END
"#,
            ),
            (
                "bridge",
                br#"TRACE-VERSION-BRIDGE-MIB DEFINITIONS ::= BEGIN
IMPORTS versionSymbol FROM TRACE-VERSION-MIB;
END
"#,
            ),
            (
                "consumer",
                br#"TRACE-VERSION-CONSUMER-MIB DEFINITIONS ::= BEGIN
IMPORTS versionSymbol FROM TRACE-VERSION-BRIDGE-MIB;
versionUse OBJECT IDENTIFIER ::= { versionSymbol 1 }
END
"#,
            ),
        ]);

        let consumer = mib.module("TRACE-VERSION-CONSUMER-MIB").unwrap();
        let provenance = consumer.import_resolution("versionSymbol").unwrap();
        assert_eq!(provenance.mode, ImportResolutionMode::Forwarded);
        assert_eq!(
            provenance
                .selected_path
                .iter()
                .map(|module| mib.module_by_id(*module).source_label().unwrap())
                .collect::<Vec<_>>(),
            ["bridge", "new-version"]
        );
        assert_eq!(
            mib.module_by_id(provenance.target.unwrap()).source_label(),
            Some("new-version")
        );
        assert!(provenance.attempts.iter().any(|attempt| attempt.selected));

        let error = mib
            .trace_symbol(
                "TRACE-VERSION-MIB::versionSymbol",
                None,
                ResolutionDomain::Oid,
            )
            .expect_err("same-name versions must make name-only scope ambiguous");
        let ResolutionTraceError::AmbiguousModuleScope { candidates, .. } = error else {
            panic!("unexpected trace error: {error}");
        };
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates
                .iter()
                .map(|scope| scope.source_label.as_deref().unwrap())
                .collect::<Vec<_>>(),
            ["new-version", "old-version"]
        );
    }

    #[test]
    fn live_forwarding_attempts_preserve_multi_symbol_short_circuit() {
        let mib = resolve_sources(&[
            (
                "first-definer",
                br#"TRACE-FIRST-DEFINER-MIB DEFINITIONS ::= BEGIN
firstSymbol OBJECT IDENTIFIER ::= { iso 424282 }
END
"#,
            ),
            (
                "later-definer",
                br#"TRACE-LATER-DEFINER-MIB DEFINITIONS ::= BEGIN
laterSymbol OBJECT IDENTIFIER ::= { iso 424283 }
END
"#,
            ),
            (
                "first-root",
                br#"TRACE-MULTI-ROOT-MIB DEFINITIONS ::= BEGIN
IMPORTS firstSymbol FROM TRACE-FIRST-DEFINER-MIB;
END
"#,
            ),
            (
                "second-root",
                br#"TRACE-MULTI-ROOT-MIB DEFINITIONS ::= BEGIN
IMPORTS laterSymbol FROM TRACE-LATER-DEFINER-MIB;
END
"#,
            ),
            (
                "short-circuit-consumer",
                br#"TRACE-SHORT-CIRCUIT-MIB DEFINITIONS ::= BEGIN
IMPORTS firstSymbol, laterSymbol FROM TRACE-MULTI-ROOT-MIB;
firstUse OBJECT IDENTIFIER ::= { firstSymbol 1 }
laterUse OBJECT IDENTIFIER ::= { laterSymbol 1 }
END
"#,
            ),
        ]);

        let consumer = mib.module("TRACE-SHORT-CIRCUIT-MIB").unwrap();
        let first = consumer.import_resolution("firstSymbol").unwrap();
        let later = consumer.import_resolution("laterSymbol").unwrap();
        assert_eq!(first.mode, ImportResolutionMode::Partial);
        assert_eq!(later.mode, ImportResolutionMode::Partial);

        let forwarding_paths = later
            .attempts
            .iter()
            .filter(|attempt| attempt.stage == ImportResolutionStage::Forwarding)
            .map(|attempt| {
                attempt
                    .path
                    .iter()
                    .map(|module| mib.module_by_id(*module).source_label().unwrap())
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        assert_eq!(forwarding_paths, [vec!["first-root"]]);
        assert!(later.attempts.iter().any(|attempt| {
            attempt.stage == ImportResolutionStage::Partial
                && attempt.selected
                && attempt
                    .path
                    .iter()
                    .map(|module| mib.module_by_id(*module).source_label().unwrap())
                    .collect::<Vec<_>>()
                    == ["second-root", "later-definer"]
        }));
    }
}
