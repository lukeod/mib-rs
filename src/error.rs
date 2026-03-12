/// Errors returned by the load function.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("no MIB sources provided")]
    NoSources,

    #[error("requested modules not found: {}", .0.join(", "))]
    MissingModules(Vec<String>),

    #[error("diagnostic threshold exceeded")]
    DiagnosticThreshold,

    #[error("source error")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("I/O error")]
    Io(#[from] std::io::Error),
}

impl LoadError {
    /// Create a Source error from any error type.
    pub fn from_source(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        LoadError::Source(Box::new(err))
    }
}
