use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};

use tracing::debug;

/// Default file extensions recognized as MIB files.
/// Empty string matches files with no extension (e.g., "IF-MIB").
pub const DEFAULT_EXTENSIONS: &[&str] = &["", ".mib", ".smi", ".txt", ".my"];

/// The content and location of a found MIB file.
pub struct FindResult {
    pub content: Vec<u8>,
    /// Path used in diagnostic messages to identify the source.
    pub path: String,
}

/// Provides access to MIB files for the loading pipeline.
pub trait Source: Send + Sync {
    /// Find returns the MIB content for the named module,
    /// or Ok(None) if the module is not available.
    fn find(&self, name: &str) -> io::Result<Option<FindResult>>;

    /// List all module names known to this source.
    fn list_modules(&self) -> io::Result<Vec<String>>;
}

/// Configuration for source implementations.
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

/// Create a Source that recursively indexes a directory tree.
/// Module names are derived from file content (scanning for DEFINITIONS headers),
/// not from filenames. First match wins for duplicate names.
pub fn dir_source(root: impl AsRef<Path>) -> io::Result<Box<dyn Source>> {
    dir_source_with_config(root, SourceConfig::default())
}

/// Create a Source with custom configuration.
pub fn dir_source_with_config(
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
            path: full_path.to_string_lossy().to_string(),
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

/// Combine multiple sources into one.
/// Find() tries each source in order, returning the first match.
/// ListModules() aggregates from all sources, deduplicating.
pub fn multi_source(sources: Vec<Box<dyn Source>>) -> Box<dyn Source> {
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
        let rel_path = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_path_buf();

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
