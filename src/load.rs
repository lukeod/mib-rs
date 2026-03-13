//! MIB loading pipeline: source discovery, parallel parsing, and resolution.
//!
//! The main entry point is [`Loader`], a builder that configures sources,
//! module restrictions, diagnostics, and strictness, then runs the full
//! pipeline via [`Loader::load`]. The free function [`load`] is equivalent.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use dashmap::DashMap;
use rayon::prelude::*;
use tracing::{debug, debug_span, info, info_span, warn};

use crate::error::LoadError;
use crate::ir;
use crate::lower;
use crate::mib::Mib;
use crate::parser;
use crate::scan;
use crate::searchpath;
use crate::source::{FindResult, Source};
use crate::types::{DiagnosticConfig, ResolverStrictness};

/// Builder for loading and resolving MIB modules.
///
/// Typical usage starts with [`Loader::new`], adds one or more [`Source`]s,
/// optionally restricts the requested modules, and finishes with
/// [`Loader::load`].
///
/// If no module list is provided, all modules visible from the configured
/// sources are loaded.
///
/// # Examples
///
/// Load a specific module from a directory:
///
/// ```no_run
/// use mib_rs::Loader;
///
/// let mib = Loader::new()
///     .source(mib_rs::source::dir("/usr/share/snmp/mibs").unwrap())
///     .modules(["IF-MIB"])
///     .load()
///     .expect("load failed");
/// ```
///
/// Load from an in-memory source:
///
/// ```no_run
/// use mib_rs::Loader;
///
/// let src = mib_rs::source::memory("MY-MIB", b"MY-MIB DEFINITIONS ::= BEGIN END".as_slice());
/// let mib = Loader::new()
///     .source(src)
///     .load()
///     .expect("load failed");
/// ```
pub struct Loader {
    sources: Vec<Box<dyn Source>>,
    modules: Option<Vec<String>>,
    resolver_strictness: ResolverStrictness,
    diag_config: DiagnosticConfig,
    system_paths: bool,
}

impl Default for Loader {
    fn default() -> Self {
        Self::new()
    }
}

impl Loader {
    /// Create a new loader with no sources.
    ///
    /// Uses [`ResolverStrictness::Normal`] and the default [`DiagnosticConfig`].
    pub fn new() -> Self {
        Loader {
            sources: Vec::new(),
            modules: None,
            resolver_strictness: ResolverStrictness::Normal,
            diag_config: DiagnosticConfig::default(),
            system_paths: false,
        }
    }

    /// Add a MIB source.
    ///
    /// Sources are searched in the order they are added. When the same module
    /// is available from multiple sources, the first matching source wins.
    pub fn source(mut self, src: Box<dyn Source>) -> Self {
        self.sources.push(src);
        self
    }

    /// Add multiple MIB sources.
    ///
    /// Sources are appended in order and searched left-to-right.
    pub fn sources(mut self, srcs: Vec<Box<dyn Source>>) -> Self {
        self.sources.extend(srcs);
        self
    }

    /// Restrict loading to the named modules and their transitive dependencies.
    ///
    /// When omitted, all modules from the configured sources are loaded.
    pub fn modules(mut self, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let names: Vec<String> = names.into_iter().map(|n| n.into()).collect();
        self.modules = Some(names);
        self
    }

    /// Set the [`DiagnosticConfig`] controlling which diagnostics are
    /// reported and which severity triggers a [`LoadError::DiagnosticThreshold`].
    pub fn diagnostic_config(mut self, config: DiagnosticConfig) -> Self {
        self.diag_config = config;
        self
    }

    /// Set the [`ResolverStrictness`] level used during resolution.
    pub fn resolver_strictness(mut self, strictness: ResolverStrictness) -> Self {
        self.resolver_strictness = strictness;
        self
    }

    /// Enable automatic discovery of system MIB directories.
    ///
    /// Probes net-snmp and libsmi config files and environment variables.
    /// Discovered paths are appended after any explicitly added sources.
    /// See [`searchpath::discover_system_paths`] for details.
    pub fn system_paths(mut self) -> Self {
        self.system_paths = true;
        self
    }
}

/// Load MIB modules from configured sources and resolve them.
///
/// This is the free-function form of [`Loader::load`]. It consumes the
/// builder, runs the full pipeline (scan, parse, lower, resolve), and
/// returns the resolved [`Mib`] or a [`LoadError`].
pub fn load(options: Loader) -> Result<Mib, LoadError> {
    let requested_module_count = options.modules.as_ref().map_or(0, Vec::len);
    let load_mode = if options.modules.is_some() {
        "modules"
    } else {
        "all"
    };
    let span = info_span!(
        target: "mib_rs::load",
        "load",
        component = "load",
        mode = load_mode,
        explicit_source_count = options.sources.len(),
        requested_module_count = requested_module_count,
        system_paths = options.system_paths,
        strictness = ?options.resolver_strictness,
        reporting = ?options.diag_config.reporting,
    );
    let _guard = span.enter();

    let mut sources = options.sources;

    if options.system_paths {
        debug!(
            target: "mib_rs::load",
            component = "load",
            phase = "source_discovery",
            "discovering system sources",
        );
        sources.extend(searchpath::discover_system_sources());
    }
    if sources.is_empty() {
        return Err(LoadError::NoSources);
    }

    let strictness = options.resolver_strictness;
    let diag_config = options.diag_config;

    let (ir_modules, requested_names) = if let Some(names) = options.modules {
        let mods = load_modules_by_name(&sources, &names, &diag_config)?;
        (mods, Some(names))
    } else {
        let mods = load_all_modules(&sources, &diag_config)?;
        (mods, None)
    };

    debug!(
        target: "mib_rs::load",
        component = "load",
        module_count = ir_modules.len(),
        phase = "resolve",
        "load pipeline complete, starting resolver",
    );
    let mib = crate::mib::resolver::resolve(ir_modules, strictness, &diag_config);

    check_load_result(&mib, &diag_config, requested_names.as_deref())?;

    info!(
        target: "mib_rs::load",
        component = "load",
        module_count = mib.modules_slice().len(),
        type_count = mib.types_slice().len(),
        node_count = mib.tree().len(),
        diagnostic_count = mib.diagnostics().len(),
        "load complete",
    );
    Ok(mib)
}

impl Loader {
    /// Execute the full load pipeline and return the resolved [`Mib`].
    ///
    /// Runs source discovery, parallel parsing, lowering, and resolution.
    /// Returns [`LoadError`] if no sources are configured, requested modules
    /// are missing, or diagnostics exceed the configured threshold.
    pub fn load(self) -> Result<Mib, LoadError> {
        load(self)
    }
}

/// Load all modules from all sources in parallel.
fn load_all_modules(
    sources: &[Box<dyn Source>],
    diag_config: &DiagnosticConfig,
) -> Result<Vec<ir::Module>, LoadError> {
    // Collect all module names, deduplicating (first source wins).
    let mut seen = HashSet::new();
    let mut all_modules: Vec<(usize, String)> = Vec::new();
    for (src_idx, src) in sources.iter().enumerate() {
        let names = src.list_modules().map_err(LoadError::Io)?;
        for name in names {
            if seen.insert(name.clone()) {
                all_modules.push((src_idx, name));
            }
        }
    }

    if all_modules.is_empty() {
        let base = collect_base_modules(HashMap::new());
        return Ok(base);
    }

    info!(
        target: "mib_rs::load",
        component = "load",
        phase = "parallel_decode",
        module_count = all_modules.len(),
        "parallel loading",
    );

    // Cache decoded files by path to avoid re-parsing multi-module files.
    let path_cache: DashMap<PathBuf, Arc<Vec<ir::Module>>> = DashMap::new();

    // Parallel load.
    let results: Result<Vec<Option<ir::Module>>, LoadError> = all_modules
        .par_iter()
        .map(|(src_idx, name)| {
            let span = debug_span!(
                target: "mib_rs::load",
                "load_module",
                component = "load",
                module = %name,
                source_index = *src_idx,
            );
            let _guard = span.enter();
            let src = &sources[*src_idx];
            let result = match src.find(name).map_err(LoadError::Io)? {
                Some(r) => r,
                None => {
                    debug!(
                        target: "mib_rs::load",
                        component = "load",
                        module = %name,
                        reason = "not_found",
                        "module not found",
                    );
                    return Ok(None);
                }
            };

            let cached = path_cache
                .entry(result.path.clone())
                .or_insert_with(|| {
                    Arc::new(decode_modules(&result.content, &result.path, diag_config))
                })
                .clone();

            // Return only the requested module from possibly multi-module file.
            let target = cached.iter().find(|m| m.name == *name).cloned();
            Ok(target)
        })
        .collect();

    let results = results?;
    let mut modules: HashMap<String, ir::Module> = HashMap::new();
    for module in results.into_iter().flatten() {
        modules.entry(module.name.clone()).or_insert(module);
    }

    info!(
        target: "mib_rs::load",
        component = "load",
        phase = "parallel_decode",
        module_count = modules.len(),
        "parallel loading complete",
    );

    Ok(collect_base_modules(modules))
}

/// Load specific modules and their dependencies sequentially.
fn load_modules_by_name(
    sources: &[Box<dyn Source>],
    names: &[String],
    diag_config: &DiagnosticConfig,
) -> Result<Vec<ir::Module>, LoadError> {
    let mut modules: HashMap<String, ir::Module> = HashMap::new();
    let mut file_cache: HashMap<PathBuf, Vec<ir::Module>> = HashMap::new();

    fn find_in_sources(
        sources: &[Box<dyn Source>],
        name: &str,
    ) -> Result<Option<FindResult>, LoadError> {
        for src in sources {
            match src.find(name).map_err(LoadError::Io)? {
                Some(result) => return Ok(Some(result)),
                None => continue,
            }
        }
        Ok(None)
    }

    fn load_one(
        name: &str,
        sources: &[Box<dyn Source>],
        modules: &mut HashMap<String, ir::Module>,
        file_cache: &mut HashMap<PathBuf, Vec<ir::Module>>,
        diag_config: &DiagnosticConfig,
    ) -> Result<(), LoadError> {
        if modules.contains_key(name) {
            return Ok(());
        }

        // Check base modules.
        if let Some(base) = lower::base_modules::get_base_module(name) {
            modules.insert(name.to_string(), base.clone());
            return Ok(());
        }

        let result = match find_in_sources(sources, name)? {
            Some(r) => r,
            None => {
                debug!(
                    target: "mib_rs::load",
                    component = "load",
                    module = %name,
                    reason = "not_found",
                    "module not found",
                );
                return Ok(());
            }
        };

        let mods = file_cache
            .entry(result.path.clone())
            .or_insert_with(|| decode_modules(&result.content, &result.path, diag_config));

        // Find the target module.
        let target = mods.iter().find(|m| m.name == name);
        let target = match target {
            Some(t) => t.clone(),
            None => return Ok(()),
        };

        // Collect import module names before inserting.
        let import_modules: Vec<String> = target
            .imports
            .iter()
            .map(|imp| imp.module.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        modules.insert(name.to_string(), target);

        // Recursively load dependencies.
        for dep in import_modules {
            load_one(&dep, sources, modules, file_cache, diag_config)?;
        }

        Ok(())
    }

    for name in names {
        load_one(name, sources, &mut modules, &mut file_cache, diag_config)?;
    }

    Ok(collect_base_modules(modules))
}

/// Ensure base modules are included and return sorted module list.
fn collect_base_modules(mut modules: HashMap<String, ir::Module>) -> Vec<ir::Module> {
    for &name in lower::base_modules::base_module_names() {
        if !modules.contains_key(name)
            && let Some(base) = lower::base_modules::get_base_module(name)
        {
            modules.insert(name.to_string(), base.clone());
        }
    }
    let mut mods: Vec<ir::Module> = modules.into_values().collect();
    mods.sort_by(|a, b| a.name.cmp(&b.name));
    mods
}

/// Run the heuristic/parse/lower pipeline on raw MIB content.
fn decode_modules(
    content: &[u8],
    source_path: &Path,
    diag_config: &DiagnosticConfig,
) -> Vec<ir::Module> {
    let path_display = source_path.display();
    let span = debug_span!(
        target: "mib_rs::load",
        "decode_modules",
        component = "load",
        path = %path_display,
        byte_count = content.len(),
    );
    let _guard = span.enter();

    if !scan::looks_like_mib_content(content) {
        debug!(
            target: "mib_rs::load",
            component = "load",
            path = %path_display,
            reason = "heuristic_rejected",
            "content rejected by heuristic",
        );
        return Vec::new();
    }

    let ast_modules = parser::parse(content, diag_config);
    let path_str = source_path.to_string_lossy();
    debug!(
        target: "mib_rs::load",
        component = "load",
        path = %path_display,
        ast_module_count = ast_modules.len(),
        "parsed source into AST modules",
    );

    let mut modules = Vec::new();
    for am in ast_modules {
        let mut module = lower::lower(am, content, diag_config);
        module.source_path = path_str.to_string();
        modules.push(module);
    }
    debug!(
        target: "mib_rs::load",
        component = "load",
        path = %path_display,
        ir_module_count = modules.len(),
        "lowered source into IR modules",
    );
    modules
}

/// Check the resolved Mib for diagnostic threshold violations and missing modules.
fn check_load_result(
    mib: &Mib,
    diag_config: &DiagnosticConfig,
    requested_modules: Option<&[String]>,
) -> Result<(), LoadError> {
    // Check for missing requested modules.
    if let Some(requested) = requested_modules {
        let mut missing = Vec::new();
        for name in requested {
            if mib.module_by_name(name).is_none() {
                missing.push(name.clone());
            }
        }
        if !missing.is_empty() {
            warn!(
                target: "mib_rs::load",
                component = "load",
                reason = "missing_requested_modules",
                missing_module_count = missing.len(),
                "requested modules not found",
            );
            return Err(LoadError::MissingModules(missing));
        }
    }

    // Check FailAt threshold.
    for d in mib.diagnostics() {
        if diag_config.should_fail(d.severity) {
            warn!(
                target: "mib_rs::load",
                component = "load",
                reason = "diagnostic_threshold",
                severity = ?d.severity,
                code = %d.code,
                "diagnostic threshold exceeded",
            );
            return Err(LoadError::DiagnosticThreshold);
        }
    }

    Ok(())
}
