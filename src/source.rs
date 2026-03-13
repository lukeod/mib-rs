//! MIB source implementations for the loading pipeline.
//!
//! A [`Source`] provides access to MIB file content by module name. The library
//! ships with directory-tree, in-memory, and chained multi-source
//! implementations.

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use tracing::debug;

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
/// The library ships with [`dir`], [`dirs()`], [`memory`], [`memory_modules`],
/// and [`chain`] constructors.
pub trait Source: Send + Sync {
    /// Return the content and path for the named module, or `Ok(None)` if
    /// this source does not contain it.
    fn find(&self, name: &str) -> io::Result<Option<FindResult>>;

    /// List all module names available from this source.
    fn list_modules(&self) -> io::Result<Vec<String>>;
}

/// Configuration for directory-based [`Source`] file matching.
///
/// Controls which file extensions are recognized as MIB files during
/// directory indexing. Use [`SourceConfig::default`] for the standard
/// set ([`DEFAULT_EXTENSIONS`]).
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
    /// Extensions are normalized to lowercase with a leading dot.
    /// An empty string matches files with no extension.
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
    index: HashMap<String, PathBuf>,
}

/// Create a [`Source`] that recursively indexes a directory tree.
///
/// Module names are derived from file content (scanning for `DEFINITIONS`
/// headers), not from filenames. When duplicate module names appear, the
/// first file encountered wins.
///
/// Uses [`DEFAULT_EXTENSIONS`] for file matching. For custom extensions,
/// use [`dir_with_config`].
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
pub fn dirs(roots: impl IntoIterator<Item = impl AsRef<Path>>) -> io::Result<Box<dyn Source>> {
    let mut sources = Vec::new();
    for root in roots {
        sources.push(dir(root)?);
    }
    Ok(chain(sources))
}

impl Source for DirSource {
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        let rel_path = match self.index.get(name) {
            Some(p) => p,
            None => return Ok(None),
        };
        let full_path = self.root.join(rel_path);
        let content = std::fs::read(&full_path)?;
        Ok(Some(FindResult {
            content,
            path: full_path,
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
fn build_tree_index(root: &Path, extensions: &[String]) -> io::Result<HashMap<String, PathBuf>> {
    let ext_set: HashSet<&str> = extensions.iter().map(|s| s.as_str()).collect();
    let mut index = HashMap::new();

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
            index.entry(name).or_insert_with(|| rel_path.clone());
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
