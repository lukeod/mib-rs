/// Errors returned by the load function.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("no MIB sources provided")]
    NoSources,

    #[error("requested modules not found: {}", .0.join(", "))]
    MissingModules(Vec<String>),

    #[error("diagnostic threshold exceeded")]
    DiagnosticThreshold,

    #[error("source error: {0}")]
    Source(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("multiple errors")]
    Multiple(Vec<LoadError>),
}
