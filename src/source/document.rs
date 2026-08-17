//! Compilation-local source document storage.

use std::fmt;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;

/// Identifies a source within one compilation.
///
/// IDs can only be allocated by [`SourceSet`]. They have no default or
/// distinguished sentinel value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct SourceId(NonZeroU32);

impl SourceId {
    fn for_index(index: usize) -> Result<Self, SourceSetError> {
        let value = index
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .and_then(NonZeroU32::new)
            .ok_or(SourceSetError::TooManySources)?;
        Ok(Self(value))
    }

    fn index(self) -> usize {
        usize::try_from(self.0.get() - 1).expect("u32 source ID fits in usize")
    }
}

impl fmt::Display for SourceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// The stable identity of source content, independent of its display label.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SourceOrigin {
    /// A file identified by its path.
    File { path: PathBuf },
    /// A source bundled into the library or another component.
    Embedded { identity: Arc<str> },
    /// An in-memory or editor buffer.
    Memory { identity: Arc<str> },
    /// A source supplied by another kind of provider.
    Custom {
        provider: Arc<str>,
        identity: Arc<str>,
    },
}

impl SourceOrigin {
    /// Identify a source by its filesystem path.
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File { path: path.into() }
    }

    /// Identify content bundled into a library or application.
    pub fn embedded(identity: impl Into<Arc<str>>) -> Self {
        Self::Embedded {
            identity: identity.into(),
        }
    }

    /// Identify an in-memory or editor document.
    pub fn memory(identity: impl Into<Arc<str>>) -> Self {
        Self::Memory {
            identity: identity.into(),
        }
    }

    /// Identify content supplied by a custom kind of provider.
    pub fn custom(provider: impl Into<Arc<str>>, identity: impl Into<Arc<str>>) -> Self {
        Self::Custom {
            provider: provider.into(),
            identity: identity.into(),
        }
    }
}

/// Byte offsets at which each line in a source begins.
///
/// The first entry is always zero, including for an empty source. Further
/// position conversions are intentionally left to the position-index slice.
#[derive(Debug)]
pub(crate) struct LineIndex {
    starts: Box<[usize]>,
}

impl LineIndex {
    fn new(bytes: &[u8]) -> Self {
        let mut starts =
            Vec::with_capacity(1 + bytes.iter().filter(|&&byte| byte == b'\n').count());
        starts.push(0);
        starts.extend(
            bytes
                .iter()
                .enumerate()
                .filter_map(|(index, &byte)| (byte == b'\n').then_some(index + 1)),
        );
        Self {
            starts: starts.into_boxed_slice(),
        }
    }

    pub(crate) fn line_count(&self) -> usize {
        self.starts.len()
    }

    pub(crate) fn line_start(&self, line_index: usize) -> Option<usize> {
        self.starts.get(line_index).copied()
    }

    pub(crate) fn line_starts(&self) -> &[usize] {
        &self.starts
    }
}

/// Immutable source content retained by a compilation.
#[derive(Debug)]
pub(crate) struct SourceDocument {
    id: SourceId,
    origin: SourceOrigin,
    label: Arc<str>,
    bytes: Arc<[u8]>,
    line_index: LineIndex,
}

impl SourceDocument {
    pub(crate) fn id(&self) -> SourceId {
        self.id
    }

    pub(crate) fn origin(&self) -> &SourceOrigin {
        &self.origin
    }

    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn line_index(&self) -> &LineIndex {
        &self.line_index
    }
}

/// Failure to retain another source in a compilation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum SourceSetError {
    /// Source byte offsets must fit in the compiler's `u32` coordinate space.
    #[error("source is too large ({len} bytes; maximum is {max})")]
    SourceTooLarge { len: usize, max: usize },
    /// All representable compilation-local IDs have been allocated.
    #[error("too many sources in one compilation")]
    TooManySources,
}

/// Owns the source documents retained for one compilation.
#[derive(Debug, Default)]
pub(crate) struct SourceSet {
    documents: Vec<Arc<SourceDocument>>,
}

impl SourceSet {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        self.documents.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.documents.is_empty()
    }

    pub(crate) fn insert(
        &mut self,
        origin: SourceOrigin,
        label: impl Into<Arc<str>>,
        bytes: Arc<[u8]>,
    ) -> Result<Arc<SourceDocument>, SourceSetError> {
        validate_source_len(bytes.len())?;
        let id = SourceId::for_index(self.documents.len())?;
        let document = Arc::new(SourceDocument {
            id,
            origin,
            label: label.into(),
            line_index: LineIndex::new(&bytes),
            bytes,
        });
        self.documents.push(Arc::clone(&document));
        Ok(document)
    }

    pub(crate) fn get(&self, id: SourceId) -> Option<&Arc<SourceDocument>> {
        self.documents.get(id.index())
    }
}

fn validate_source_len(len: usize) -> Result<(), SourceSetError> {
    let max = u32::MAX as usize;
    if len > max {
        return Err(SourceSetError::SourceTooLarge { len, max });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_origin(identity: &str) -> SourceOrigin {
        SourceOrigin::Memory {
            identity: Arc::from(identity),
        }
    }

    #[test]
    fn source_set_allocates_nonzero_unique_ids() {
        let mut sources = SourceSet::new();
        let first = sources
            .insert(memory_origin("buffer:one"), "one", Arc::from(&b"one"[..]))
            .unwrap();
        let second = sources
            .insert(memory_origin("buffer:two"), "two", Arc::from(&b"two"[..]))
            .unwrap();

        assert_ne!(first.id(), second.id());
        assert_eq!(first.id().to_string(), "1");
        assert_eq!(second.id().to_string(), "2");
        assert_eq!(sources.len(), 2);
        assert!(!sources.is_empty());
    }

    #[test]
    fn origin_identity_is_distinct_from_display_label() {
        let mut sources = SourceSet::new();
        let origin = SourceOrigin::Custom {
            provider: Arc::from("workspace"),
            identity: Arc::from("document/42"),
        };
        let document = sources
            .insert(origin.clone(), "ACME-MIB", Arc::from(&b"contents"[..]))
            .unwrap();

        assert_eq!(document.origin(), &origin);
        assert_eq!(document.label(), "ACME-MIB");
        assert_ne!(document.label(), "document/42");
    }

    #[test]
    fn document_retains_shared_bytes_without_copying() {
        let bytes: Arc<[u8]> = Arc::from(&b"first\nsecond"[..]);
        let mut sources = SourceSet::new();
        let document = sources
            .insert(memory_origin("buffer"), "buffer", Arc::clone(&bytes))
            .unwrap();

        assert_eq!(document.bytes(), bytes.as_ref());
        assert_eq!(document.bytes().as_ptr(), bytes.as_ptr());
        assert_eq!(Arc::strong_count(&bytes), 2);
    }

    #[test]
    fn source_lookup_checks_id_bounds() {
        let mut sources = SourceSet::new();
        let document = sources
            .insert(memory_origin("buffer"), "buffer", Arc::from(&b""[..]))
            .unwrap();

        assert!(Arc::ptr_eq(sources.get(document.id()).unwrap(), &document));
        assert!(sources.get(SourceId::for_index(1).unwrap()).is_none());
    }

    #[test]
    fn line_index_owns_all_line_starts_and_checks_bounds() {
        let mut sources = SourceSet::new();
        let document = sources
            .insert(
                memory_origin("buffer"),
                "buffer",
                Arc::from(&b"first\n\nthird\n"[..]),
            )
            .unwrap();
        let index = document.line_index();

        assert_eq!(index.line_starts(), &[0, 6, 7, 13]);
        assert_eq!(index.line_count(), 4);
        assert_eq!(index.line_start(0), Some(0));
        assert_eq!(index.line_start(3), Some(13));
        assert_eq!(index.line_start(4), None);
    }

    #[test]
    fn all_origin_kinds_retain_typed_identity() {
        let origins = [
            SourceOrigin::File {
                path: PathBuf::from("/mibs/IF-MIB"),
            },
            SourceOrigin::Embedded {
                identity: Arc::from("SNMPv2-SMI"),
            },
            memory_origin("untitled:1"),
            SourceOrigin::Custom {
                provider: Arc::from("database"),
                identity: Arc::from("mib/7"),
            },
        ];

        assert_eq!(origins.len(), 4);
        assert!(origins.iter().all(|origin| origins.contains(origin)));
    }

    #[test]
    fn rejects_unrepresentable_source_lengths_and_id_overflow() {
        let too_large = (u32::MAX as usize).checked_add(1).unwrap();
        assert_eq!(
            validate_source_len(too_large),
            Err(SourceSetError::SourceTooLarge {
                len: too_large,
                max: u32::MAX as usize,
            })
        );
        assert_eq!(
            SourceId::for_index(u32::MAX as usize),
            Err(SourceSetError::TooManySources)
        );
    }
}
