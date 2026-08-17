//! MIB source implementations for the loading pipeline.
//!
//! A [`Source`] provides access to MIB source documents by module name. The library
//! ships with directory-tree, in-memory, and chained multi-source
//! implementations.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::debug;

use crate::lower::base_modules;
use crate::scan;

#[allow(dead_code)]
mod document;

pub use document::{
    ByteOffset, SourceDocument, SourceId, SourceOrigin, SourceRange, SourceRangeError, SourceSet,
};

/// Default file extensions recognized as MIB files.
///
/// The empty string matches files with no extension (e.g., `IF-MIB`).
pub const DEFAULT_EXTENSIONS: &[&str] = &["", ".mib", ".smi", ".txt", ".my"];

/// Identifies one physical candidate within a [`Source`] implementation.
///
/// Candidate identities are scoped to the source that returns them. The same
/// identity returned for different requested module names tells the loader
/// that both names refer to the same physical document. An identity must stay
/// associated with the same origin and content for the duration of a load.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateId(Arc<str>);

impl CandidateId {
    /// Create a provider-scoped candidate identity.
    pub fn new(identity: impl Into<Arc<str>>) -> Self {
        Self(identity.into())
    }

    /// Return the provider-local identity text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn scoped(&self, scope: usize) -> Self {
        Self::new(format!("{scope}:{}:{}", self.0.len(), self.0))
    }
}

impl fmt::Display for CandidateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl From<&str> for CandidateId {
    fn from(identity: &str) -> Self {
        Self::new(identity)
    }
}

impl From<String> for CandidateId {
    fn from(identity: String) -> Self {
        Self::new(identity)
    }
}

impl From<Arc<str>> for CandidateId {
    fn from(identity: Arc<str>) -> Self {
        Self(identity)
    }
}

/// A physical source document advertised as a candidate for a module name.
///
/// Its provider-scoped [`CandidateId`], physical [`SourceOrigin`], display
/// label, and immutable bytes are independent. In particular, custom and
/// in-memory sources do not need to invent filesystem paths.
#[derive(Clone, Debug)]
pub struct SourceCandidate {
    identity: CandidateId,
    origin: SourceOrigin,
    label: Arc<str>,
    bytes: Arc<[u8]>,
}

impl SourceCandidate {
    /// Create a source candidate.
    pub fn new(
        identity: impl Into<CandidateId>,
        origin: SourceOrigin,
        label: impl Into<Arc<str>>,
        bytes: impl Into<Arc<[u8]>>,
    ) -> Self {
        Self {
            identity: identity.into(),
            origin,
            label: label.into(),
            bytes: bytes.into(),
        }
    }

    /// Return this candidate's stable identity within its provider.
    pub fn identity(&self) -> &CandidateId {
        &self.identity
    }

    /// Return the physical origin of the document.
    pub fn origin(&self) -> &SourceOrigin {
        &self.origin
    }

    /// Return the label used to identify the document to users.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the immutable source bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the shared allocation containing the immutable source bytes.
    pub fn shared_bytes(&self) -> &Arc<[u8]> {
        &self.bytes
    }

    fn with_scoped_identity(mut self, scope: usize) -> Self {
        self.identity = self.identity.scoped(scope);
        self
    }
}

/// Provides access to MIB files for the loading pipeline.
///
/// Implementations must be `Send + Sync` to support parallel loading.
/// The library ships several constructors:
///
/// - [`file()`] / [`files()`] - individual files on disk
/// - [`dir`] / [`dir_with_config`] - directory tree on disk
/// - [`dirs()`] - multiple directory trees combined
/// - [`memory`] / [`memory_modules`] - in-memory content
/// - [`chain`] - combine arbitrary sources in priority order
pub trait Source: Send + Sync {
    /// Look up a module by name and return its first document candidate.
    ///
    /// Returns `Ok(None)` if this source does not contain the named module.
    /// The `name` parameter is the MIB module name (e.g. `"IF-MIB"`), not a
    /// filename.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the underlying storage cannot be read (for
    /// example, a file I/O failure or permission denial).
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>>;

    /// Iterate over candidates for a module name in precedence order.
    ///
    /// Candidates and their I/O errors are produced lazily. This lets callers
    /// stop after validating an earlier candidate without accessing lower
    /// priority storage. Each candidate supplies a stable provider-scoped
    /// identity; returning the same identity for multiple requested names
    /// associates those names with one physical document. Custom sources that
    /// expose at most one candidate can rely on this default implementation.
    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<SourceCandidate>> + 'a> {
        Box::new(
            std::iter::once_with(move || self.find(name)).filter_map(|result| result.transpose()),
        )
    }

    /// List all module names available from this source.
    ///
    /// The returned names should match what [`find`](Source::find) accepts.
    /// Callers use this to discover modules when no explicit module list is
    /// provided to the loader.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if listing fails (e.g. directory read error).
    fn list_modules(&self) -> io::Result<Vec<String>>;
}

/// A final fallback source for the embedded SMI foundation modules.
pub(crate) struct EmbeddedSource;

impl Source for EmbeddedSource {
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>> {
        Ok(base_modules::embedded_content(name).map(|content| {
            SourceCandidate::new(
                name,
                SourceOrigin::embedded(name),
                format!("embedded:{name}"),
                Arc::<[u8]>::from(content),
            )
        }))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        Ok(base_modules::base_module_names()
            .iter()
            .map(|name| (*name).to_string())
            .collect())
    }
}

/// Configuration for directory-based [`Source`] file matching.
///
/// Controls which file extensions are recognized as MIB files during
/// directory indexing. Use [`SourceConfig::default`] for the standard
/// set ([`DEFAULT_EXTENSIONS`]).
///
/// # Examples
///
/// ```
/// let config = mib_rs::source::SourceConfig::default()
///     .with_extensions(&[".mib", ".txt"]);
/// ```
#[derive(Clone)]
pub struct SourceConfig {
    extensions: Vec<String>,
}

impl Default for SourceConfig {
    fn default() -> Self {
        SourceConfig {
            extensions: DEFAULT_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl SourceConfig {
    /// Override the default file extensions used to match MIB files.
    ///
    /// Extensions are normalized to lowercase with a leading dot.
    /// An empty string (`""`) matches files with no extension (e.g. `IF-MIB`).
    pub fn with_extensions(mut self, exts: &[&str]) -> Self {
        self.extensions = exts
            .iter()
            .map(|ext| {
                let ext = ext.to_lowercase();
                if !ext.is_empty() && !ext.starts_with('.') {
                    format!(".{ext}")
                } else {
                    ext
                }
            })
            .collect();
        self
    }
}

/// A source backed by a directory tree on disk.
/// The directory is eagerly indexed at construction time.
struct DirSource {
    root: PathBuf,
    index: HashMap<String, Vec<(usize, PathBuf)>>,
}

/// Create a [`Source`] that recursively indexes a directory tree.
///
/// Module names are derived from file content (scanning for `DEFINITIONS`
/// headers), not from filenames. When duplicate module names appear, their
/// files are retained in traversal order and validated when loaded.
///
/// The directory is eagerly indexed at construction time, so all file I/O
/// for discovery happens during this call rather than during later
/// [`Source::find`] lookups.
///
/// Uses [`DEFAULT_EXTENSIONS`] for file matching. For custom extensions,
/// use [`dir_with_config`].
///
/// # Errors
///
/// Returns [`io::Error`] if `root` does not exist, is not a directory,
/// or cannot be read.
///
/// # Examples
///
/// ```no_run
/// let src = mib_rs::source::dir("/usr/share/snmp/mibs").unwrap();
/// let modules = src.list_modules().unwrap();
/// ```
pub fn dir(root: impl AsRef<Path>) -> io::Result<Box<dyn Source>> {
    dir_with_config(root, SourceConfig::default())
}

/// Create a [`Source`] backed by a directory tree with custom [`SourceConfig`].
///
/// Like [`dir`], but allows overriding file extension matching via
/// [`SourceConfig::with_extensions`].
///
/// # Errors
///
/// Returns [`io::Error`] if `root` does not exist or is not a directory.
pub fn dir_with_config(
    root: impl AsRef<Path>,
    config: SourceConfig,
) -> io::Result<Box<dyn Source>> {
    let root = root.as_ref();
    let meta = std::fs::metadata(root)?;
    if !meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("not a directory: {}", root.display()),
        ));
    }
    let index = build_tree_index(root, &config.extensions)?;
    Ok(Box::new(DirSource {
        root: root.to_path_buf(),
        index,
    }))
}

/// Create a [`Source`] that chains multiple directory trees.
///
/// Equivalent to calling [`dir`] on each root and combining with [`chain`].
///
/// # Errors
///
/// Returns [`io::Error`] if any root does not exist or is not a directory.
pub fn dirs(roots: impl IntoIterator<Item = impl AsRef<Path>>) -> io::Result<Box<dyn Source>> {
    let mut sources = Vec::new();
    for root in roots {
        sources.push(dir(root)?);
    }
    Ok(chain(sources))
}

impl Source for DirSource {
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>> {
        self.find_candidates(name).next().transpose()
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<SourceCandidate>> + 'a> {
        let entries = self.index.get(name).into_iter().flatten();
        Box::new(entries.filter_map(move |(document_index, rel_path)| {
            let full_path = self.root.join(rel_path);
            let content = match std::fs::read(&full_path) {
                Ok(content) => content,
                Err(error) => return Some(Err(error)),
            };
            // The eagerly built index can become stale if a file changes
            // before loading. Discard stale candidates without hiding later
            // files indexed under the same module name.
            scan::scan_module_names(&content)
                .iter()
                .any(|candidate| candidate == name)
                .then_some(Ok(SourceCandidate::new(
                    document_index.to_string(),
                    SourceOrigin::file(full_path.clone()),
                    full_path.to_string_lossy().into_owned(),
                    Arc::<[u8]>::from(content),
                )))
        }))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        let mut names: Vec<String> = self.index.keys().cloned().collect();
        names.sort();
        Ok(names)
    }
}

/// A source combining multiple sources in order.
/// Find() tries each source in order, returning the first match.
struct MultiSource {
    sources: Vec<Box<dyn Source>>,
}

/// Combine multiple [`Source`]s into one.
///
/// [`Source::find`] tries each source in order, returning the first match.
/// [`Source::find_candidates`] retains every child candidate in child order so
/// loaders can continue after an advertisement fails decode validation.
/// [`Source::list_modules`] aggregates all sources, deduplicating by name.
pub fn chain(sources: Vec<Box<dyn Source>>) -> Box<dyn Source> {
    Box::new(MultiSource { sources })
}

impl Source for MultiSource {
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>> {
        for (index, src) in self.sources.iter().enumerate() {
            match src.find(name)? {
                Some(result) => return Ok(Some(result.with_scoped_identity(index))),
                None => continue,
            }
        }
        Ok(None)
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<SourceCandidate>> + 'a> {
        Box::new(
            self.sources
                .iter()
                .enumerate()
                .flat_map(move |(index, source)| {
                    source.find_candidates(name).map(move |candidate| {
                        candidate.map(|item| item.with_scoped_identity(index))
                    })
                }),
        )
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        let mut seen = HashSet::new();
        let mut names = Vec::new();
        for src in &self.sources {
            for name in src.list_modules()? {
                if seen.insert(name.clone()) {
                    names.push(name);
                }
            }
        }
        Ok(names)
    }
}

/// Create a [`Source`] from a single MIB file on disk.
///
/// The module name is extracted from the file content by scanning for
/// `DEFINITIONS ::=` headers, just like [`dir`] does for directory trees.
/// The caller does not need to know or provide the module name.
///
/// # Errors
///
/// Returns [`io::Error`] if the file cannot be read or does not contain
/// a valid module definition.
///
/// # Examples
///
/// ```no_run
/// let src = mib_rs::source::file("/path/to/IF-MIB.mib").unwrap();
/// assert!(src.list_modules().unwrap().contains(&"IF-MIB".to_string()));
/// ```
pub fn file(path: impl AsRef<Path>) -> io::Result<Box<dyn Source>> {
    files([path])
}

/// Create a [`Source`] from multiple MIB files on disk.
///
/// Module names are extracted from each file's content by scanning for
/// `DEFINITIONS ::=` headers. Duplicate module names retain all files in input
/// order so the loader can validate candidates before applying precedence.
///
/// Files without a loadable module header are skipped so they cannot hide a
/// valid later path.
///
/// # Errors
///
/// Returns [`io::Error`] if any file cannot be read, or if none of the files
/// contain a valid module definition.
pub fn files(paths: impl IntoIterator<Item = impl AsRef<Path>>) -> io::Result<Box<dyn Source>> {
    let mut modules = HashMap::new();
    let mut documents = Vec::new();
    let mut first_path = None;
    for path in paths {
        let path = path.as_ref();
        first_path.get_or_insert_with(|| path.to_path_buf());
        let content = std::fs::read(path)?;
        let names = crate::scan::scan_module_names(&content);
        let document_index = documents.len();
        let diag_path = path.to_path_buf();
        documents.push((diag_path.clone(), Arc::<[u8]>::from(content)));
        for name in names {
            modules
                .entry(name)
                .or_insert_with(Vec::new)
                .push(document_index);
        }
    }
    if modules.is_empty() {
        let location = first_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "file list".to_string());
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("no module definition found in {location}"),
        ));
    }
    Ok(Box::new(FileSource { modules, documents }))
}

/// A source backed by file contents grouped by advertised module name.
struct FileSource {
    modules: HashMap<String, Vec<usize>>,
    documents: Vec<(PathBuf, Arc<[u8]>)>,
}

impl Source for FileSource {
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>> {
        self.find_candidates(name).next().transpose()
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<SourceCandidate>> + 'a> {
        Box::new(
            self.modules
                .get(name)
                .into_iter()
                .flatten()
                .map(|&document_index| {
                    let (path, bytes) = &self.documents[document_index];
                    Ok(SourceCandidate::new(
                        document_index.to_string(),
                        SourceOrigin::file(path.clone()),
                        path.to_string_lossy().into_owned(),
                        Arc::clone(bytes),
                    ))
                }),
        )
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        let mut names: Vec<String> = self.modules.keys().cloned().collect();
        names.sort();
        Ok(names)
    }
}

/// A source backed by in-memory byte buffers keyed by module name.
struct MemorySource {
    modules: HashMap<String, Arc<[u8]>>,
}

/// Create a [`Source`] backed by a single in-memory MIB module.
///
/// Useful for testing or embedding MIB text directly in code.
///
/// # Examples
///
/// ```
/// let src = mib_rs::source::memory(
///     "MY-MIB",
///     b"MY-MIB DEFINITIONS ::= BEGIN END".as_slice(),
/// );
/// assert_eq!(src.list_modules().unwrap(), vec!["MY-MIB"]);
/// ```
pub fn memory(name: impl Into<String>, bytes: impl Into<Vec<u8>>) -> Box<dyn Source> {
    memory_modules([(name.into(), bytes.into())])
}

/// Create a [`Source`] backed by multiple in-memory MIB modules.
///
/// Each entry is a `(name, bytes)` pair. Module names must match the
/// `DEFINITIONS` header inside the corresponding content.
pub fn memory_modules(
    modules: impl IntoIterator<Item = (impl Into<String>, impl Into<Vec<u8>>)>,
) -> Box<dyn Source> {
    let mut map = HashMap::new();
    for (name, bytes) in modules {
        let name = name.into();
        map.insert(name, Arc::from(bytes.into()));
    }
    Box::new(MemorySource { modules: map })
}

impl Source for MemorySource {
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>> {
        Ok(self.modules.get(name).map(|bytes| {
            SourceCandidate::new(
                name,
                SourceOrigin::memory(name),
                format!("<memory:{name}>"),
                Arc::clone(bytes),
            )
        }))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        let mut names: Vec<String> = self.modules.keys().cloned().collect();
        names.sort();
        Ok(names)
    }
}

/// Build a module name -> relative path index by walking a directory tree.
fn build_tree_index(
    root: &Path,
    extensions: &[String],
) -> io::Result<HashMap<String, Vec<(usize, PathBuf)>>> {
    let ext_set: HashSet<&str> = extensions.iter().map(|s| s.as_str()).collect();
    let mut index: HashMap<String, Vec<(usize, PathBuf)>> = HashMap::new();
    let mut document_index = 0;

    for entry in walkdir::WalkDir::new(root).into_iter() {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                debug!(
                    target: "mib_rs::source",
                    component = "source",
                    reason = "walkdir_error",
                    error = %e,
                    "skipping directory entry",
                );
                continue;
            }
        };

        if entry.file_type().is_dir() {
            continue;
        }

        let path = entry.path();
        if !has_valid_extension(path, &ext_set) {
            continue;
        }

        let content = match std::fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                debug!(
                    target: "mib_rs::source",
                    component = "source",
                    path = %path.display(),
                    reason = "read_error",
                    error = %e,
                    "cannot read file",
                );
                continue;
            }
        };

        let names = crate::scan::scan_module_names(&content);
        let rel_path = path.strip_prefix(root).unwrap_or(path).to_path_buf();

        for name in names {
            index
                .entry(name)
                .or_default()
                .push((document_index, rel_path.clone()));
        }
        document_index += 1;
    }

    Ok(index)
}

fn has_valid_extension(path: &Path, ext_set: &HashSet<&str>) -> bool {
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
        .unwrap_or_default();
    ext_set.contains(ext.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_check() {
        let ext_set: HashSet<&str> = vec!["", ".mib", ".smi"].into_iter().collect();
        assert!(has_valid_extension(Path::new("IF-MIB"), &ext_set));
        assert!(has_valid_extension(Path::new("test.mib"), &ext_set));
        assert!(has_valid_extension(Path::new("test.MIB"), &ext_set));
        assert!(!has_valid_extension(Path::new("test.txt"), &ext_set));
    }

    #[test]
    fn candidate_retains_shared_bytes_and_independent_metadata() {
        let bytes: Arc<[u8]> = Arc::from(&b"contents"[..]);
        let candidate = SourceCandidate::new(
            "document-42",
            SourceOrigin::custom("workspace", "buffer-42"),
            "ACME-MIB (modified)",
            Arc::clone(&bytes),
        );

        assert_eq!(candidate.identity().as_str(), "document-42");
        assert_eq!(
            candidate.origin(),
            &SourceOrigin::custom("workspace", "buffer-42")
        );
        assert_eq!(candidate.label(), "ACME-MIB (modified)");
        assert_eq!(candidate.bytes().as_ptr(), bytes.as_ptr());
        assert!(Arc::ptr_eq(candidate.shared_bytes(), &bytes));
    }

    #[test]
    fn built_in_non_file_sources_use_typed_origins() {
        let memory = memory("DISPLAY-NAME", b"bytes".as_slice());
        let memory_candidate = memory.find("DISPLAY-NAME").unwrap().unwrap();
        assert_eq!(
            memory_candidate.origin(),
            &SourceOrigin::memory("DISPLAY-NAME")
        );
        assert_eq!(memory_candidate.label(), "<memory:DISPLAY-NAME>");

        let embedded = EmbeddedSource
            .find("SNMPv2-SMI")
            .unwrap()
            .expect("embedded module");
        assert_eq!(embedded.origin(), &SourceOrigin::embedded("SNMPv2-SMI"));
        assert_eq!(embedded.label(), "embedded:SNMPv2-SMI");
    }
}
