//! Resolver: transforms IR modules into a fully resolved [`Mib`].
//!
//! Resolution runs six sequential, single-threaded phases:
//!
//! - **Registration** - Index modules, create resolved module shells, seed base modules.
//! - **Imports** - Resolve cross-module symbol references, handle forwarding and aliases.
//! - **Types** - Build type graph, resolve parent chains, inherit base types and constraints.
//! - **OIDs** - Build OID trie from symbolic references in topological order.
//! - **Semantics** - Infer node kinds, create Objects/Notifications/Groups, resolve indexes.
//! - **Checks** - Post-resolution validation (access rules, naming conventions, etc.).
//!
//! All phases are infallible: errors are collected as diagnostics rather than causing
//! early termination, so the output contains as much useful data as possible.

mod checks;
mod context;
mod imports;
mod oids;
mod registration;
mod semantics;
mod types;
mod util;

use crate::ir;
use crate::types::{DiagnosticConfig, ResolverStrictness};
use tracing::{debug, debug_span, info, info_span, warn};

use super::mib::Mib;
use context::ResolverContext;

/// Resolve a set of parsed IR modules into a fully resolved [`Mib`].
///
/// Runs six sequential phases: registration, imports, types, OIDs, semantics, checks.
/// All phases are single-threaded and infallible - errors are collected as
/// [`Diagnostic`](crate::types::Diagnostic) values rather than causing early
/// termination, so the output contains as much useful data as possible.
///
/// The `strictness` parameter controls fallback behavior (e.g., whether
/// unimported SMI types are resolved via global lookup). The `diag_config`
/// controls which diagnostics are reported.
pub fn resolve(
    modules: Vec<ir::Module>,
    strictness: ResolverStrictness,
    diag_config: &DiagnosticConfig,
) -> Mib {
    let input_modules = modules.len();
    let span = info_span!(
        target: "mib_rs::resolver",
        "resolve",
        component = "resolver",
        module_count = input_modules,
        strictness = ?strictness,
        reporting = ?diag_config.reporting,
    );
    let _guard = span.enter();

    let mut ctx = ResolverContext::new(strictness, diag_config.clone());

    run_phase("registration", || {
        registration::register_modules(&mut ctx, modules);
        debug!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "registration",
            module_count = ctx.mib.modules_slice().len(),
            diagnostic_count = ctx.mib.diagnostics().len(),
            "phase complete",
        );
    });
    run_phase("imports", || {
        imports::resolve_imports(&mut ctx);
        imports::resolve_transitive_imports(&mut ctx);
        debug!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "imports",
            resolved_module_count = ctx.module_imports.len(),
            unresolved_import_count = ctx.unresolved_imports.len(),
            "phase complete",
        );
    });
    run_phase("types", || {
        types::resolve_types(&mut ctx);
        types::check_basetype_imports(&mut ctx);
        debug!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "types",
            type_count = ctx.mib.types_slice().len(),
            unresolved_type_count = ctx.unresolved_types.len(),
            "phase complete",
        );
    });
    run_phase("oids", || {
        oids::resolve_oids(&mut ctx);
        debug!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "oids",
            node_count = ctx.mib.tree().len(),
            unresolved_oid_count = ctx.unresolved_oids.len(),
            "phase complete",
        );
    });
    run_phase("semantics", || {
        semantics::resolve_semantics(&mut ctx);
        debug!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "semantics",
            object_count = ctx.mib.objects_slice().len(),
            notification_count = ctx.mib.notifications_slice().len(),
            group_count = ctx.mib.groups_slice().len(),
            compliance_count = ctx.mib.compliances_slice().len(),
            capability_count = ctx.mib.capabilities_slice().len(),
            unresolved_index_count = ctx.unresolved_indexes.len(),
            unresolved_notification_object_count = ctx.unresolved_notif_objects.len(),
            "phase complete",
        );
    });
    run_phase("checks", || {
        imports::check_unused_imports(&mut ctx);
        imports::check_obsolete_imports(&mut ctx);
        imports::copy_used_imports_to_modules(&mut ctx);
        imports::copy_resolved_imports_to_modules(&mut ctx);
        checks::run_checks(&mut ctx);
        debug!(
            target: "mib_rs::resolver",
            component = "resolver",
            phase = "checks",
            diagnostic_count = ctx.mib.diagnostics().len(),
            "phase complete",
        );
    });

    ctx.drop_modules();
    ctx.finalize_unresolved();
    let node_count = ctx.mib.tree().len();
    ctx.mib.set_node_count(node_count);

    if !ctx.unresolved_imports.is_empty() {
        warn!(
            target: "mib_rs::resolver",
            component = "resolver",
            unresolved_import_count = ctx.unresolved_imports.len(),
            "unresolved imports",
        );
    }
    if !ctx.unresolved_types.is_empty() {
        warn!(
            target: "mib_rs::resolver",
            component = "resolver",
            unresolved_type_count = ctx.unresolved_types.len(),
            "unresolved types",
        );
    }
    if !ctx.unresolved_oids.is_empty() {
        warn!(
            target: "mib_rs::resolver",
            component = "resolver",
            unresolved_oid_count = ctx.unresolved_oids.len(),
            "unresolved oids",
        );
    }
    if !ctx.unresolved_indexes.is_empty() {
        warn!(
            target: "mib_rs::resolver",
            component = "resolver",
            unresolved_index_count = ctx.unresolved_indexes.len(),
            "unresolved indexes",
        );
    }
    if !ctx.unresolved_notif_objects.is_empty() {
        warn!(
            target: "mib_rs::resolver",
            component = "resolver",
            unresolved_notification_object_count = ctx.unresolved_notif_objects.len(),
            "unresolved notification objects",
        );
    }

    info!(
        target: "mib_rs::resolver",
        component = "resolver",
        module_count = ctx.mib.modules_slice().len(),
        type_count = ctx.mib.types_slice().len(),
        node_count = node_count,
        diagnostic_count = ctx.mib.diagnostics().len(),
        "resolution complete",
    );
    ctx.mib
}

fn run_phase<F>(phase: &'static str, f: F)
where
    F: FnOnce(),
{
    let span = debug_span!(
        target: "mib_rs::resolver",
        "phase",
        component = "resolver",
        phase = phase,
    );
    let _guard = span.enter();
    debug!(
        target: "mib_rs::resolver",
        component = "resolver",
        phase = phase,
        "starting phase",
    );
    f();
}
