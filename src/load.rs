//! MIB loading pipeline: source discovery, parallel parsing, and resolution.
//!
//! The main entry point is [`Loader`], a builder that configures sources,
//! module restrictions, diagnostics, and strictness, then runs the full
//! pipeline via [`Loader::load`]. The free function [`load`] is equivalent.

use std::collections::{HashMap, HashSet};
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
use crate::source::{CandidateId, Source, SourceCandidate, SourceDocument, SourceSet};
use crate::types::{Diagnostic, DiagnosticConfig, ResolverStrictness};

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
/// Embedded foundation modules (SNMPv2-SMI, SNMPv2-TC, etc.) are used as
/// lowest-priority fallbacks when configured sources do not provide them.
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

    let has_explicit_sources = !options.sources.is_empty();
    let has_requested_modules = options.modules.is_some();
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
    if !has_explicit_sources && !options.system_paths && !has_requested_modules {
        return Err(LoadError::NoSources);
    }
    sources.push(Box::new(crate::source::EmbeddedSource));

    let strictness = options.resolver_strictness;
    let diag_config = options.diag_config;

    let (loaded, requested_names) = if let Some(names) = options.modules {
        let loaded = load_modules_by_name(&sources, &names, &diag_config)?;
        (loaded, Some(names))
    } else {
        let loaded = load_all_modules(&sources, &diag_config, options.parallelism)?;
        (loaded, None)
    };

    debug!(
        target: "mib_rs::load",
        component = "load",
        module_count = loaded.modules.len(),
        phase = "resolve",
        "load pipeline complete, starting resolver",
    );
    let mib =
        crate::mib::resolver::resolve(loaded.modules, loaded.sources, strictness, &diag_config);

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
    use crate::source::SourceOrigin;
    use crate::types::{DiagCode, Severity, Span};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, Condvar, mpsc};
    use std::time::Duration;

    #[derive(Clone)]
    struct SharedDocumentSource {
        names: Vec<String>,
        candidate: SourceCandidate,
    }

    impl SharedDocumentSource {
        fn new(
            names: impl IntoIterator<Item = impl Into<String>>,
            identity: &str,
            origin: SourceOrigin,
            label: &str,
            bytes: Arc<[u8]>,
        ) -> Self {
            Self {
                names: names.into_iter().map(Into::into).collect(),
                candidate: SourceCandidate::new(identity, origin, label, bytes),
            }
        }
    }

    impl Source for SharedDocumentSource {
        fn find(&self, name: &str) -> std::io::Result<Option<SourceCandidate>> {
            Ok(self
                .names
                .iter()
                .any(|candidate| candidate == name)
                .then(|| self.candidate.clone()))
        }

        fn list_modules(&self) -> std::io::Result<Vec<String>> {
            Ok(self.names.clone())
        }
    }

    fn module_document<'a>(mib: &'a Mib, name: &str) -> &'a SourceDocument {
        let module_id = mib
            .module_by_name(name)
            .unwrap_or_else(|| panic!("missing module {name}"));
        let source_id = mib
            .raw()
            .module(module_id)
            .source_id
            .unwrap_or_else(|| panic!("module {name} has no source"));
        mib.sources
            .get(source_id)
            .unwrap_or_else(|| panic!("source {} is not retained", source_id))
    }

    fn cache_key(index: usize) -> CandidateKey {
        (0, CandidateId::new(format!("TEST-{index}")))
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

    #[test]
    fn source_registry_interns_provider_candidate_once() {
        let bytes: Arc<[u8]> = Arc::from(&b"A-MIB DEFINITIONS ::= BEGIN END"[..]);
        let candidate = SourceCandidate::new(
            "document-7",
            crate::source::SourceOrigin::memory("buffer-7"),
            "untitled MIB",
            Arc::clone(&bytes),
        );
        let mut registry = SourceRegistry::default();

        let (first_key, first) = registry.intern(3, &candidate).unwrap();
        let (second_key, second) = registry.intern(3, &candidate).unwrap();

        assert_eq!(first_key, second_key);
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(registry.sources.len(), 1);
        assert_eq!(first.bytes().as_ptr(), bytes.as_ptr());
    }

    #[test]
    fn candidate_identity_is_scoped_by_provider() {
        let bytes: Arc<[u8]> = Arc::from(&b"contents"[..]);
        let candidate = SourceCandidate::new(
            "shared-id",
            crate::source::SourceOrigin::memory("shared-id"),
            "shared",
            bytes,
        );
        let mut registry = SourceRegistry::default();

        let (_, first) = registry.intern(0, &candidate).unwrap();
        let (_, second) = registry.intern(1, &candidate).unwrap();

        assert_ne!(first.id(), second.id());
        assert_eq!(registry.sources.len(), 2);
    }

    #[test]
    fn modules_from_one_document_share_source_id_in_parallel_loading() {
        let content: Arc<[u8]> = Arc::from(
            &br#"
FIRST-MIB DEFINITIONS ::= BEGIN END
SECOND-MIB DEFINITIONS ::= BEGIN END
"#[..],
        );
        let source = SharedDocumentSource::new(
            ["FIRST-MIB", "SECOND-MIB"],
            "both-modules",
            SourceOrigin::custom("test", "both-modules"),
            "two modules",
            content,
        );

        let mib = Loader::new()
            .source(Box::new(source))
            .parallelism(4)
            .load()
            .expect("multi-module document should load");

        let first = module_document(&mib, "FIRST-MIB");
        let second = module_document(&mib, "SECOND-MIB");
        assert_eq!(first.id(), second.id());
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn distinct_documents_have_distinct_source_ids() {
        let mib = Loader::new()
            .source(crate::source::memory_modules([
                (
                    "FIRST-MIB",
                    b"FIRST-MIB DEFINITIONS ::= BEGIN END".as_slice(),
                ),
                (
                    "SECOND-MIB",
                    b"SECOND-MIB DEFINITIONS ::= BEGIN END".as_slice(),
                ),
            ]))
            .modules(["FIRST-MIB", "SECOND-MIB"])
            .load()
            .expect("separate memory documents should load");

        assert_ne!(
            module_document(&mib, "FIRST-MIB").id(),
            module_document(&mib, "SECOND-MIB").id()
        );
    }

    #[test]
    fn mib_retains_document_and_original_bytes_after_registry_drops() {
        let bytes: Arc<[u8]> = Arc::from(&b"RETAINED-MIB DEFINITIONS ::= BEGIN END"[..]);
        let weak_bytes = Arc::downgrade(&bytes);
        let expected_pointer = bytes.as_ptr();
        let source = SharedDocumentSource::new(
            ["RETAINED-MIB"],
            "retained",
            SourceOrigin::custom("test", "retained"),
            "retained source",
            Arc::clone(&bytes),
        );
        drop(bytes);

        let mib = Loader::new()
            .source(Box::new(source))
            .modules(["RETAINED-MIB"])
            .load()
            .expect("retained source should load");

        let document = module_document(&mib, "RETAINED-MIB");
        assert_eq!(document.bytes().as_ptr(), expected_pointer);
        assert_eq!(
            weak_bytes
                .upgrade()
                .expect("Mib should retain source bytes")
                .as_ptr(),
            expected_pointer
        );

        drop(mib);
        assert!(weak_bytes.upgrade().is_none());
    }

    #[test]
    fn resolved_modules_reach_all_source_origin_kinds() {
        static TEMP_FILE_COUNTER: AtomicUsize = AtomicUsize::new(0);

        let file_path = std::env::temp_dir().join(format!(
            "mib-rs-source-origin-{}-{}.mib",
            std::process::id(),
            TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&file_path, b"FILE-ORIGIN-MIB DEFINITIONS ::= BEGIN END")
            .expect("write temporary MIB");
        let file_source = crate::source::file(&file_path).expect("create file source");

        let custom = SharedDocumentSource::new(
            ["CUSTOM-ORIGIN-MIB"],
            "custom-origin",
            SourceOrigin::custom("database", "record-7"),
            "database record 7",
            Arc::from(&b"CUSTOM-ORIGIN-MIB DEFINITIONS ::= BEGIN END"[..]),
        );
        let result = Loader::new()
            .source(file_source)
            .source(crate::source::memory(
                "MEMORY-ORIGIN-MIB",
                b"MEMORY-ORIGIN-MIB DEFINITIONS ::= BEGIN END".as_slice(),
            ))
            .source(Box::new(custom))
            .modules([
                "FILE-ORIGIN-MIB",
                "MEMORY-ORIGIN-MIB",
                "CUSTOM-ORIGIN-MIB",
                "SNMPv2-SMI",
            ])
            .load();
        std::fs::remove_file(&file_path).expect("remove temporary MIB");
        let mib = result.expect("all source origin kinds should load");

        assert!(matches!(
            module_document(&mib, "FILE-ORIGIN-MIB").origin(),
            SourceOrigin::File { path } if path == &file_path
        ));
        assert_eq!(
            module_document(&mib, "MEMORY-ORIGIN-MIB").origin(),
            &SourceOrigin::memory("MEMORY-ORIGIN-MIB")
        );
        assert_eq!(
            module_document(&mib, "CUSTOM-ORIGIN-MIB").origin(),
            &SourceOrigin::custom("database", "record-7")
        );
        assert_eq!(
            module_document(&mib, "SNMPv2-SMI").origin(),
            &SourceOrigin::embedded("SNMPv2-SMI")
        );
    }

    #[test]
    fn generated_records_have_no_source_id() {
        let module = ir::Module::new("GENERATED-MIB".to_string(), Span::SYNTHETIC);
        assert!(module.source_id.is_none());

        let resolved = crate::mib::module::ModuleData::new("GENERATED-MIB".to_string());
        assert!(resolved.source_id.is_none());

        let mib = Mib::new();
        assert!(mib.sources.is_empty());
        assert!(mib.tree.get(mib.tree.root()).module.is_none());

        let mib = Loader::new()
            .modules(["SNMPv2-SMI"])
            .load()
            .expect("embedded foundation should load");
        assert_eq!(
            module_document(&mib, "SNMPv2-SMI").origin(),
            &SourceOrigin::embedded("SNMPv2-SMI")
        );
        assert!(
            mib.r#type("INTEGER")
                .expect("generated primitive")
                .span()
                .is_synthetic()
        );
        assert!(mib.root_node().span().is_synthetic());
    }

    #[test]
    fn threshold_failure_releases_retained_sources() {
        let bytes: Arc<[u8]> = Arc::from(
            &br#"LEAK-CHECK-MIB { 01 } DEFINITIONS ::= BEGIN
badName OBJECT IDENTIFIER ::= { iso 99999 }
END
"#[..],
        );
        let weak_bytes = Arc::downgrade(&bytes);
        let source = SharedDocumentSource::new(
            ["LEAK-CHECK-MIB"],
            "leak-check",
            SourceOrigin::memory("leak-check"),
            "leak check",
            Arc::clone(&bytes),
        );
        drop(bytes);
        let mut diagnostics = DiagnosticConfig::default();
        diagnostics
            .overrides
            .insert(DiagCode::NumberLeadingZero, Severity::Severe);

        let result = Loader::new()
            .source(Box::new(source))
            .modules(["LEAK-CHECK-MIB"])
            .diagnostic_config(diagnostics)
            .load();

        assert!(matches!(result, Err(LoadError::DiagnosticThreshold { .. })));
        assert!(weak_bytes.upgrade().is_none());
    }
}

impl Loader {
    /// Execute the full load pipeline and return the resolved [`Mib`].
    ///
    /// Runs source discovery, parallel parsing, lowering, and resolution.
    ///
    /// # Errors
    ///
    /// Returns [`LoadError::NoSources`] if neither sources, system paths, nor
    /// an explicit module selection are configured,
    /// [`LoadError::MissingModules`] if explicitly requested modules cannot
    /// be found, [`LoadError::DiagnosticThreshold`] if any diagnostic
    /// exceeds the configured severity threshold, or [`LoadError::Io`] on
    /// file read failures.
    pub fn load(self) -> Result<Mib, LoadError> {
        load(self)
    }
}

type CandidateKey = (usize, CandidateId);
type ModuleCacheEntry = Arc<OnceLock<Arc<Vec<ir::Module>>>>;
type SharedModuleCache = Mutex<HashMap<CandidateKey, ModuleCacheEntry>>;

#[derive(Debug, Default)]
struct SourceRegistry {
    sources: SourceSet,
    documents: HashMap<CandidateKey, Arc<SourceDocument>>,
}

impl SourceRegistry {
    fn intern(
        &mut self,
        provider_index: usize,
        candidate: &SourceCandidate,
    ) -> Result<(CandidateKey, Arc<SourceDocument>), LoadError> {
        let key = (provider_index, candidate.identity().clone());
        if let Some(document) = self.documents.get(&key) {
            return Ok((key, Arc::clone(document)));
        }

        let document = self
            .sources
            .insert(
                candidate.origin().clone(),
                candidate.label(),
                Arc::clone(candidate.shared_bytes()),
            )
            .map_err(LoadError::from_source)?;
        self.documents.insert(key.clone(), Arc::clone(&document));
        Ok((key, document))
    }

    fn into_sources(self) -> SourceSet {
        self.sources
    }
}

struct LoadedModules {
    modules: Vec<ir::Module>,
    sources: SourceSet,
}

fn cached_modules(
    cache: &SharedModuleCache,
    key: CandidateKey,
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
) -> Result<LoadedModules, LoadError> {
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

    info!(
        target: "mib_rs::load",
        component = "load",
        phase = "parallel_decode",
        module_count = all_modules.len(),
        "parallel loading",
    );

    // Cache each provider-scoped physical candidate independently of the
    // module name through which it was discovered.
    let document_cache: SharedModuleCache = Mutex::new(HashMap::new());
    let source_registry = Mutex::new(SourceRegistry::default());

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
                        for result in src.find_candidates(&candidate.name) {
                            let result = match result {
                                Ok(result) => result,
                                Err(error_value) => {
                                    *error.lock().unwrap() = Some(LoadError::Io(error_value));
                                    break 'sources;
                                }
                            };
                            let (key, document) = match source_registry
                                .lock()
                                .unwrap()
                                .intern(candidate.source_index, &result)
                            {
                                Ok(interned) => interned,
                                Err(error_value) => {
                                    *error.lock().unwrap() = Some(error_value);
                                    break 'sources;
                                }
                            };
                            let cached = cached_modules(&document_cache, key, || {
                                decode_modules(&document, diag_config)
                            });

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
                                source = result.label(),
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

    let registry = source_registry.into_inner().unwrap();
    Ok(LoadedModules {
        modules: collect_modules(modules),
        sources: registry.into_sources(),
    })
}

/// Load specific modules and their dependencies sequentially.
fn load_modules_by_name(
    sources: &[Box<dyn Source>],
    names: &[String],
    diag_config: &DiagnosticConfig,
) -> Result<LoadedModules, LoadError> {
    let mut modules: HashMap<String, ir::Module> = HashMap::new();
    let mut document_cache: HashMap<CandidateKey, Vec<ir::Module>> = HashMap::new();
    let mut source_registry = SourceRegistry::default();

    fn load_one(
        name: &str,
        sources: &[Box<dyn Source>],
        modules: &mut HashMap<String, ir::Module>,
        document_cache: &mut HashMap<CandidateKey, Vec<ir::Module>>,
        source_registry: &mut SourceRegistry,
        diag_config: &DiagnosticConfig,
    ) -> Result<(), LoadError> {
        if modules.contains_key(name) {
            return Ok(());
        }

        // A Source::find result is only a candidate until decoding confirms
        // that its content contains the requested module. Phantom source
        // advertisements must not shadow valid modules in later sources.
        let mut target = None;
        'sources: for (source_index, source) in sources.iter().enumerate() {
            for result in source.find_candidates(name) {
                let result = result.map_err(LoadError::Io)?;
                let (key, document) = source_registry.intern(source_index, &result)?;
                let mods = document_cache
                    .entry(key)
                    .or_insert_with(|| decode_modules(&document, diag_config));
                if let Some(module) = mods.iter().find(|module| module.name == name) {
                    target = Some(module.clone());
                    break 'sources;
                }

                debug!(
                    target: "mib_rs::load",
                    component = "load",
                    module = %name,
                    source = result.label(),
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
            load_one(
                &dep,
                sources,
                modules,
                document_cache,
                source_registry,
                diag_config,
            )?;
        }

        Ok(())
    }

    for name in names {
        load_one(
            name,
            sources,
            &mut modules,
            &mut document_cache,
            &mut source_registry,
            diag_config,
        )?;
    }

    // Foundation modules are always present, with configured sources taking
    // precedence over the embedded fallback on a per-module basis.
    for name in lower::base_modules::base_module_names() {
        load_one(
            name,
            sources,
            &mut modules,
            &mut document_cache,
            &mut source_registry,
            diag_config,
        )?;
    }

    Ok(LoadedModules {
        modules: collect_modules(modules),
        sources: source_registry.into_sources(),
    })
}

/// Return modules sorted by name.
fn collect_modules(modules: HashMap<String, ir::Module>) -> Vec<ir::Module> {
    let mut mods: Vec<ir::Module> = modules.into_values().collect();
    mods.sort_by(|a, b| a.name.cmp(&b.name));
    mods
}

/// Run the heuristic/parse/lower pipeline on raw MIB content.
fn decode_modules(document: &SourceDocument, diag_config: &DiagnosticConfig) -> Vec<ir::Module> {
    let content = document.bytes();
    let source_label = document.label();
    let span = debug_span!(
        target: "mib_rs::load",
        "decode_modules",
        component = "load",
        source = source_label,
        byte_count = content.len(),
    );
    let _guard = span.enter();

    if !scan::looks_like_mib_content(content) {
        debug!(
            target: "mib_rs::load",
            component = "load",
            source = source_label,
            reason = "heuristic_rejected",
            "content rejected by heuristic",
        );
        return Vec::new();
    }

    let ast_modules = parser::parse(content, diag_config);
    debug!(
        target: "mib_rs::load",
        component = "load",
        source = source_label,
        ast_module_count = ast_modules.len(),
        "parsed source into AST modules",
    );

    let mut modules = Vec::new();
    for am in ast_modules {
        let mut module = lower::lower(am, content, diag_config);
        module.source_path = source_label.to_string();
        module.source_id = Some(document.id());
        modules.push(module);
    }
    debug!(
        target: "mib_rs::load",
        component = "load",
        source = source_label,
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
    if let Some(diagnostic) = mib
        .diagnostics()
        .iter()
        .find(|diagnostic| diag_config.should_fail(diagnostic.severity))
    {
        warn!(
            target: "mib_rs::load",
            component = "load",
            reason = "diagnostic_threshold",
            severity = ?diagnostic.severity,
            code = %diagnostic.code,
            "diagnostic threshold exceeded",
        );

        let mut diagnostics = mib.diagnostics().to_vec();
        sort_diagnostics(&mut diagnostics);
        return Err(LoadError::DiagnosticThreshold { diagnostics });
    }

    Ok(())
}

/// Sort diagnostics using the canonical order also used by resolved-MIB export.
fn sort_diagnostics(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by(|left, right| {
        left.code
            .phase()
            .cmp(right.code.phase())
            .then_with(|| left.code.as_code().cmp(right.code.as_code()))
            .then(left.severity.cmp(&right.severity))
            .then(left.module.cmp(&right.module))
            .then(left.line.cmp(&right.line))
            .then(left.column.cmp(&right.column))
            .then(left.message.cmp(&right.message))
    });
}
