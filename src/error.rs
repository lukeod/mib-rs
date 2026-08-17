//! Error types for the MIB loading pipeline.
//!
//! The primary error type is [`LoadError`], returned by [`Loader::load`](crate::Loader::load)
//! and the free function [`load`](crate::load::load).

use crate::types::Diagnostic;

/// Errors returned by [`Loader::load`](crate::Loader::load) and the
/// free function [`load`](crate::load::load).
///
/// All variants carry enough context for callers to present useful error
/// messages. The [`Display`](std::fmt::Display) implementation produces
/// human-readable text for each case.
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
    /// `diagnostics` contains every diagnostic collected during the load, not
    /// only those at or above the failure threshold. The diagnostics are
    /// ordered by pipeline phase, code, effective severity, module, source
    /// location, and message.
    ///
    /// See [`DiagnosticConfig`](crate::DiagnosticConfig) for threshold configuration.
    #[error("diagnostic threshold exceeded")]
    DiagnosticThreshold {
        /// All diagnostics collected during the failed load, in deterministic order.
        diagnostics: Vec<Diagnostic>,
    },

    /// A [`Source`](crate::Source) implementation returned a custom error.
    ///
    /// Use [`LoadError::from_source`] to construct this variant from an
    /// arbitrary error type.
    #[error("source error")]
    Source(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// An I/O error occurred while reading MIB files from disk.
    #[error("I/O error")]
    Io(#[from] std::io::Error),
}

impl LoadError {
    /// Wrap an arbitrary error as a [`LoadError::Source`].
    ///
    /// Useful for custom [`Source`](crate::Source) implementations that
    /// need to return domain-specific errors through the loading pipeline.
    pub fn from_source(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        LoadError::Source(Box::new(err))
    }
}
