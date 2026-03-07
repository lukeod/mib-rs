mod checks;
mod context;
mod imports;
mod oids;
mod registration;
mod semantics;
mod types;
mod util;

use crate::ir;
use crate::types::DiagnosticConfig;

use super::mib::Mib;
use context::ResolverContext;

/// Resolve a set of parsed IR modules into a fully resolved Mib.
///
/// Runs five sequential phases: registration, imports, types, OIDs, semantics.
/// All phases are single-threaded and infallible (errors become diagnostics).
pub fn resolve(modules: Vec<ir::Module>, diag_config: &DiagnosticConfig) -> Mib {
    let mut ctx = ResolverContext::new(modules, diag_config.clone());

    registration::register_modules(&mut ctx);
    imports::resolve_imports(&mut ctx);
    imports::resolve_transitive_imports(&mut ctx);
    types::resolve_types(&mut ctx);
    types::check_basetype_imports(&mut ctx);
    oids::resolve_oids(&mut ctx);
    semantics::resolve_semantics(&mut ctx);

    imports::check_unused_imports(&mut ctx);
    imports::check_obsolete_imports(&mut ctx);
    imports::copy_used_imports_to_modules(&mut ctx);
    imports::copy_resolved_imports_to_modules(&mut ctx);

    checks::run_checks(&mut ctx);

    ctx.drop_modules();
    ctx.finalize_unresolved();
    let node_count = ctx.mib.tree().len();
    ctx.mib.set_node_count(node_count);
    ctx.mib
}
