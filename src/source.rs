//! MIB source implementations for the loading pipeline.
//!
//! A [`Source`] provides access to MIB file content by module name. The library
//! ships with directory-tree, in-memory, and chained multi-source
//! implementations.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::scan;

/// Default file extensions recognized as MIB files.
///
/// The empty string matches files with no extension (e.g., `IF-MIB`).
pub const DEFAULT_EXTENSIONS: &[&str] = &["", ".mib", ".smi", ".txt", ".my"];

/// The content and location of a found MIB file.
///
/// Returned by [`Source::find`] when a module is located.
pub struct FindResult {
    /// Raw file content (bytes, not necessarily UTF-8).
    pub content: Vec<u8>,
    /// Path used in diagnostic messages to identify the source.
    ///
    /// For on-disk sources this is the absolute file path. For in-memory
    /// sources it is a synthetic label like `<memory:MY-MIB>`.
    pub path: PathBuf,
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
    /// Look up a module by name and return its content and source path.
    ///
    /// Returns `Ok(None)` if this source does not contain the named module.
    /// The `name` parameter is the MIB module name (e.g. `"IF-MIB"`), not a
    /// filename.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if the underlying storage cannot be read (e.g.
    /// file I/O failure, permission denied).
    fn find(&self, name: &str) -> io::Result<Option<FindResult>>;

    /// Iterate over candidates for a module name in precedence order.
    ///
    /// Candidates and their I/O errors are produced lazily. This lets callers
    /// stop after validating an earlier candidate without accessing lower
    /// priority storage. Each candidate is independently identified by its
    /// position as well as its diagnostic path. Custom sources that expose at
    /// most one candidate can rely on this default implementation.
    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<FindResult>> + 'a> {
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
    index: HashMap<String, Vec<PathBuf>>,
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
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        self.find_candidates(name).next().transpose()
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<FindResult>> + 'a> {
        let rel_paths = self.index.get(name).into_iter().flatten();
        Box::new(rel_paths.filter_map(move |rel_path| {
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
                .then_some(Ok(FindResult {
                    content,
                    path: full_path,
                }))
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
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        for src in &self.sources {
            match src.find(name)? {
                Some(result) => return Ok(Some(result)),
                None => continue,
            }
        }
        Ok(None)
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<FindResult>> + 'a> {
        Box::new(
            self.sources
                .iter()
                .flat_map(move |source| source.find_candidates(name)),
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
    let mut first_path = None;
    for path in paths {
        let path = path.as_ref();
        first_path.get_or_insert_with(|| path.to_path_buf());
        let content = std::fs::read(path)?;
        let names = crate::scan::scan_module_names(&content);
        let diag_path = path.to_path_buf();
        for name in names {
            modules
                .entry(name)
                .or_insert_with(Vec::new)
                .push((diag_path.clone(), content.clone()));
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
    Ok(Box::new(FileSource { modules }))
}

/// A source backed by file contents grouped by advertised module name.
struct FileSource {
    modules: HashMap<String, Vec<(PathBuf, Vec<u8>)>>,
}

impl Source for FileSource {
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        self.find_candidates(name).next().transpose()
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<FindResult>> + 'a> {
        Box::new(
            self.modules
                .get(name)
                .into_iter()
                .flatten()
                .map(|(path, content)| {
                    Ok(FindResult {
                        content: content.clone(),
                        path: path.clone(),
                    })
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
    modules: HashMap<String, (PathBuf, Vec<u8>)>,
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
        map.insert(
            name.clone(),
            (PathBuf::from(format!("<memory:{name}>")), bytes.into()),
        );
    }
    Box::new(MemorySource { modules: map })
}

impl Source for MemorySource {
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        Ok(self.modules.get(name).map(|(path, content)| FindResult {
            content: content.clone(),
            path: path.clone(),
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
) -> io::Result<HashMap<String, Vec<PathBuf>>> {
    let ext_set: HashSet<&str> = extensions.iter().map(|s| s.as_str()).collect();
    let mut index: HashMap<String, Vec<PathBuf>> = HashMap::new();

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
            index.entry(name).or_default().push(rel_path.clone());
        }
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
}
