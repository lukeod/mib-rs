//! MIB loading pipeline: source discovery, parallel parsing, and resolution.
//!
//! The main entry point is [`Loader`], a builder that configures sources,
//! module restrictions, diagnostics, and strictness, then runs the full
//! pipeline via [`Loader::load`]. The free function [`load`] is equivalent.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, debug_span, info, info_span, warn};

use crate::error::LoadError;
use crate::ir;
use crate::lower;
use crate::mib::Mib;
use crate::parser;
use crate::scan;
use crate::searchpath;
use crate::source::Source;
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
    parallelism: Option<usize>,
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
            parallelism: None,
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

    /// Set the [`DiagnosticConfig`] controlling diagnostic collection,
    /// severity overrides, and the [`LoadError::DiagnosticThreshold`].
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

    /// Set the number of threads used when loading all discoverable modules.
    ///
    /// Defaults to the number of available logical CPUs. Set to `1` to
    /// disable parallel loading. Loading a selected module list with
    /// [`Loader::modules`] and resolving parsed modules are sequential.
    pub fn parallelism(mut self, threads: usize) -> Self {
        self.parallelism = Some(threads.max(1));
        self
    }
}

/// Load MIB modules from configured sources and resolve them.
///
/// This is the free-function form of [`Loader::load`]. It consumes the
/// [`Loader`] builder, runs the full pipeline (scan, parse, lower, resolve),
/// and returns the resolved [`Mib`] or a [`LoadError`].
///
/// Synthetic base modules (SNMPv2-SMI, SNMPv2-TC, etc.) are always included
/// automatically, even if no external sources provide them.
///
/// # Errors
///
/// See [`Loader::load`] for the full list of error conditions.
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
        let mods = load_all_modules(&sources, &diag_config, options.parallelism)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, Condvar, mpsc};
    use std::time::Duration;

    fn cache_key(index: usize) -> FileCacheKey {
        (0, format!("TEST-{index}"), index, PathBuf::from("<test>"))
    }

    #[test]
    fn cache_initializes_distinct_entries_concurrently() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (started_tx, started_rx) = mpsc::channel();
        let mut handles = Vec::new();

        for index in 0..2 {
            let cache = Arc::clone(&cache);
            let gate = Arc::clone(&gate);
            let started_tx = started_tx.clone();
            handles.push(std::thread::spawn(move || {
                cached_modules(&cache, cache_key(index), || {
                    started_tx.send(index).unwrap();
                    let (released, wake) = &*gate;
                    let mut released = released.lock().unwrap();
                    while !*released {
                        released = wake.wait(released).unwrap();
                    }
                    Vec::new()
                })
            }));
        }
        drop(started_tx);

        let first_started = started_rx.recv_timeout(Duration::from_secs(5));
        let second_started = started_rx.recv_timeout(Duration::from_secs(5));

        let (released, wake) = &*gate;
        *released.lock().unwrap() = true;
        wake.notify_all();
        for handle in handles {
            handle.join().unwrap();
        }

        assert!(first_started.is_ok(), "no cache initializer started");
        assert!(
            second_started.is_ok(),
            "distinct cache entry was blocked by another entry's initializer"
        );
    }

    #[test]
    fn cache_initializes_shared_entry_once() {
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let start = Arc::new(Barrier::new(3));
        let initialization_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();

        for _ in 0..2 {
            let cache = Arc::clone(&cache);
            let start = Arc::clone(&start);
            let initialization_count = Arc::clone(&initialization_count);
            handles.push(std::thread::spawn(move || {
                start.wait();
                cached_modules(&cache, cache_key(0), || {
                    initialization_count.fetch_add(1, Ordering::Relaxed);
                    Vec::new()
                })
            }));
        }
        start.wait();

        let first = handles.remove(0).join().unwrap();
        let second = handles.remove(0).join().unwrap();
        assert_eq!(initialization_count.load(Ordering::Relaxed), 1);
        assert!(Arc::ptr_eq(&first, &second));
    }
}

impl Loader {
    /// Execute the full load pipeline and return the resolved [`Mib`].
    ///
    /// Runs source discovery, parallel parsing, lowering, and resolution.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::NoSources`] if no sources are configured,
    /// [`LoadError::MissingModules`] if explicitly requested modules cannot
    /// be found, [`LoadError::DiagnosticThreshold`] if any diagnostic
    /// exceeds the configured severity threshold, or [`LoadError::Io`] on
    /// file read failures.
    pub fn load(self) -> Result<Mib, LoadError> {
        load(self)
    }
}

type FileCacheKey = (usize, String, usize, PathBuf);
type ModuleCacheEntry = Arc<OnceLock<Arc<Vec<ir::Module>>>>;
type SharedModuleCache = Mutex<HashMap<FileCacheKey, ModuleCacheEntry>>;

fn cached_modules(
    cache: &SharedModuleCache,
    key: FileCacheKey,
    decode: impl FnOnce() -> Vec<ir::Module>,
) -> Arc<Vec<ir::Module>> {
    let entry = {
        let mut cache = cache.lock().unwrap();
        cache
            .entry(key)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone()
    };

    entry.get_or_init(|| Arc::new(decode())).clone()
}

#[derive(Debug)]
struct ModuleCandidate {
    source_index: usize,
    name: String,
}

/// Load all modules from all sources in parallel.
fn load_all_modules(
    sources: &[Box<dyn Source>],
    diag_config: &DiagnosticConfig,
    parallelism: Option<usize>,
) -> Result<Vec<ir::Module>, LoadError> {
    // Keep every source advertising a name until decoding confirms which
    // candidate actually contains the module. Only then is precedence fixed.
    let mut module_indexes = HashMap::<String, usize>::new();
    let mut all_modules: Vec<(String, Vec<ModuleCandidate>)> = Vec::new();
    for (source_index, source) in sources.iter().enumerate() {
        let names = source.list_modules().map_err(LoadError::Io)?;
        let mut seen_in_source = HashSet::new();
        for name in names {
            if !seen_in_source.insert(name.clone()) {
                continue;
            }
            let candidate = ModuleCandidate {
                source_index,
                name: name.clone(),
            };
            if let Some(&index) = module_indexes.get(&name) {
                all_modules[index].1.push(candidate);
            } else {
                module_indexes.insert(name.clone(), all_modules.len());
                all_modules.push((name, vec![candidate]));
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

    // Cache decoded candidates without conflating module-specific lookups or
    // sources that reuse candidate positions and diagnostic paths.
    let path_cache: SharedModuleCache = Mutex::new(HashMap::new());

    // Parallel load using std::thread::scope with an atomic work queue.
    let thread_count =
        parallelism.unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let next_idx = AtomicUsize::new(0);
    let error: Mutex<Option<LoadError>> = Mutex::new(None);
    let collected: Mutex<HashMap<String, ir::Module>> = Mutex::new(HashMap::new());

    std::thread::scope(|s| {
        for _ in 0..thread_count {
            s.spawn(|| {
                let mut local_modules: Vec<(String, ir::Module)> = Vec::new();
                loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= all_modules.len() {
                        break;
                    }
                    // Check if another thread hit an error.
                    if error.lock().unwrap().is_some() {
                        break;
                    }

                    let (name, candidates) = &all_modules[idx];
                    let span = debug_span!(
                        target: "mib_rs::load",
                        "load_module",
                        component = "load",
                        module = %name,
                    );
                    let _guard = span.enter();

                    'sources: for candidate in candidates {
                        let src = &sources[candidate.source_index];
                        for (candidate_index, result) in
                            src.find_candidates(&candidate.name).enumerate()
                        {
                            let result = match result {
                                Ok(result) => result,
                                Err(error_value) => {
                                    *error.lock().unwrap() = Some(LoadError::Io(error_value));
                                    break 'sources;
                                }
                            };
                            let cached = cached_modules(
                                &path_cache,
                                (
                                    candidate.source_index,
                                    name.clone(),
                                    candidate_index,
                                    result.path.clone(),
                                ),
                                || decode_modules(&result.content, &result.path, diag_config),
                            );

                            // A source advertisement is only a candidate until
                            // its decoded content contains the requested module.
                            if let Some(target) = cached.iter().find(|m| m.name == *name) {
                                local_modules.push((name.clone(), target.clone()));
                                break 'sources;
                            }
                            debug!(
                                target: "mib_rs::load",
                                component = "load",
                                module = %name,
                                source_index = candidate.source_index,
                                path = %result.path.display(),
                                reason = "decoded_module_missing",
                                "candidate did not contain advertised module",
                            );
                        }
                    }
                }
                // Merge local results.
                let mut map = collected.lock().unwrap();
                for (name, module) in local_modules {
                    map.entry(name).or_insert(module);
                }
            });
        }
    });

    if let Some(e) = error.into_inner().unwrap() {
        return Err(e);
    }
    let modules = collected.into_inner().unwrap();

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
    let mut file_cache: HashMap<FileCacheKey, Vec<ir::Module>> = HashMap::new();

    fn load_one(
        name: &str,
        sources: &[Box<dyn Source>],
        modules: &mut HashMap<String, ir::Module>,
        file_cache: &mut HashMap<FileCacheKey, Vec<ir::Module>>,
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

        // A Source::find result is only a candidate until decoding confirms
        // that its content contains the requested module. Phantom source
        // advertisements must not shadow valid modules in later sources.
        let mut target = None;
        'sources: for (source_index, source) in sources.iter().enumerate() {
            for (candidate_index, result) in source.find_candidates(name).enumerate() {
                let result = result.map_err(LoadError::Io)?;
                let mods = file_cache
                    .entry((
                        source_index,
                        name.to_string(),
                        candidate_index,
                        result.path.clone(),
                    ))
                    .or_insert_with(|| decode_modules(&result.content, &result.path, diag_config));
                if let Some(module) = mods.iter().find(|module| module.name == name) {
                    target = Some(module.clone());
                    break 'sources;
                }

                debug!(
                    target: "mib_rs::load",
                    component = "load",
                    module = %name,
                    path = %result.path.display(),
                    reason = "decoded_module_missing",
                    "candidate did not contain advertised module",
                );
            }
        }

        let target = match target {
            Some(target) => target,
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
