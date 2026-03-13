//! Error types for the MIB loading pipeline.

/// Errors returned by [`Loader::load`](crate::Loader::load) and the
/// free function [`load`](crate::load::load).
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    /// No [`Source`](crate::Source)s were configured on the [`Loader`](crate::Loader).
    #[error("no MIB sources provided")]
    NoSources,

    /// One or more explicitly requested modules were not found after resolution.
    ///
    /// The contained `Vec` lists the missing module names.
    #[error("requested modules not found: {}", .0.join(", "))]
    MissingModules(Vec<String>),

    /// A diagnostic exceeded the configured fail-at severity threshold.
    ///
    /// See [`DiagnosticConfig`](crate::DiagnosticConfig) for threshold configuration.
    #[error("diagnostic threshold exceeded")]
    DiagnosticThreshold,

    /// A [`Source`](crate::Source) implementation returned a custom error.
    #[error("source error")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// An I/O error occurred while reading MIB files from disk.
    #[error("I/O error")]
    Io(#[from] std::io::Error),
}

impl LoadError {
    /// Wrap an arbitrary error as a [`LoadError::Source`].
    pub fn from_source(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        LoadError::Source(Box::new(err))
    }
}
