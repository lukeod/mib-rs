//! Diagnostic reporting and configuration.
//!
//! [`Diagnostic`] represents a single issue found during parsing or resolution.
//! [`DiagnosticConfig`] controls diagnostic collection, presentation, severity
//! overrides, and load failure thresholds, with preset configurations for
//! common use cases.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::source::{
    BytePosition, Position, PositionEncoding, PositionError, SourceDocument, SourceId,
    SourceOrigin, SourceRange, SourceRangeError, SourceSet,
};

use super::{DiagCode, ReportingLevel, Severity};

/// An issue found during parsing or resolution.
///
/// Its [`severity`](Self::severity) is the effective severity after applying
/// [`DiagnosticConfig::overrides`]. Source locations remain checked,
/// source-qualified byte ranges; line and column values are derived by a
/// report-owned [`DiagnosticEntry`] handles when needed for presentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Effective severity after applying diagnostic configuration overrides.
    pub severity: Severity,
    /// Diagnostic code identifying the issue category.
    pub code: DiagCode,
    /// Human-readable description of the issue.
    pub message: String,
    /// Module name where the issue was found, if applicable.
    pub module: Option<String>,
    /// Exact half-open source range, or `None` for a generated/source-less issue.
    pub range: Option<SourceRange>,
}

impl fmt::Display for Diagnostic {
    /// Formats without a source position; use [`DiagnosticEntry::render`] to
    /// include a checked, derived location.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.severity)?;
        if let Some(module) = &self.module {
            write!(f, " {module}:")?;
        }
        write!(f, " {}", self.message)
    }
}

/// An ordered diagnostic collection that retains all referenced source documents.
///
/// Cloning a report shares immutable source documents; diagnostic values are
/// cloned because they are small presentation records.
/// Reports are returned by [`Mib::diagnostic_report`](crate::Mib::diagnostic_report),
/// the lossless CST entry points [`cst::parse`](crate::cst::parse) and
/// [`cst::parse_with_config`](crate::cst::parse_with_config), and
/// [`LoadError::DiagnosticThreshold`](crate::LoadError::DiagnosticThreshold).
/// Each report keeps every diagnostic tied to the exact source arena that
/// allocated its IDs.
///
/// ```compile_fail
/// use std::sync::Arc;
/// use mib_rs::{DiagnosticReport, SourceSet};
///
/// // Arbitrary diagnostic/source association is intentionally unavailable.
/// let report = DiagnosticReport::new(Vec::new(), Arc::new(SourceSet::new()));
/// ```
///
/// Checked operations belong to report-owned entries rather than accepting a
/// free [`Diagnostic`] reference:
///
/// ```compile_fail
/// # fn reports() -> (mib_rs::DiagnosticReport, mib_rs::DiagnosticReport) { todo!() }
/// let (first, second) = reports();
/// let foreign = &first.diagnostics()[0];
/// let location = second.range(foreign);
/// ```
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    diagnostics: Vec<Diagnostic>,
    sources: Arc<SourceSet>,
}

impl DiagnosticReport {
    pub(crate) fn new(mut diagnostics: Vec<Diagnostic>, sources: Arc<SourceSet>) -> Self {
        sort_diagnostics(&mut diagnostics, &sources);
        Self {
            diagnostics,
            sources,
        }
    }

    /// Return the number of diagnostics in this report.
    pub fn len(&self) -> usize {
        self.diagnostics.len()
    }

    /// Return whether this report contains no diagnostics.
    pub fn is_empty(&self) -> bool {
        self.diagnostics.is_empty()
    }

    /// Return diagnostics in canonical deterministic order.
    ///
    /// This slice exposes metadata only. Use [`Self::iter`] or [`Self::get`] to
    /// obtain a report-owned [`DiagnosticEntry`] for checked source operations.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Iterate over report-owned diagnostic entries in canonical order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = DiagnosticEntry<'_>> + DoubleEndedIterator {
        (0..self.diagnostics.len()).map(|index| DiagnosticEntry {
            report: self,
            index,
        })
    }

    /// Return a report-owned diagnostic entry by canonical-order index.
    pub fn get(&self, index: usize) -> Option<DiagnosticEntry<'_>> {
        (index < self.diagnostics.len()).then_some(DiagnosticEntry {
            report: self,
            index,
        })
    }

    #[cfg(test)]
    pub(crate) fn shared_sources(&self) -> &Arc<SourceSet> {
        &self.sources
    }
}

/// A diagnostic tied to the report that owns its source arena.
///
/// Entries are created only by [`DiagnosticReport::iter`] and
/// [`DiagnosticReport::get`]. Checked range and position methods therefore
/// cannot accidentally resolve a diagnostic through another report whose
/// compilation-local source IDs happen to have the same numeric value.
#[derive(Clone, Copy, Debug)]
pub struct DiagnosticEntry<'report> {
    report: &'report DiagnosticReport,
    index: usize,
}

impl<'report> DiagnosticEntry<'report> {
    /// Return the diagnostic metadata owned by this entry's report.
    pub fn diagnostic(&self) -> &'report Diagnostic {
        &self.report.diagnostics[self.index]
    }

    /// Resolve and validate a diagnostic's optional source range.
    pub fn range(
        &self,
    ) -> Result<Option<(&'report SourceDocument, SourceRange)>, DiagnosticReportError> {
        let diagnostic = self.diagnostic();
        let Some(range) = diagnostic.range else {
            return Ok(None);
        };
        let source = self
            .report
            .sources
            .get(range.source())
            .ok_or(DiagnosticReportError::SourceNotRetained(range.source()))?;
        source.slice(range)?;
        Ok(Some((source, range)))
    }

    /// Return the checked bytes covered by a diagnostic's range.
    pub fn slice(&self) -> Result<Option<&'report [u8]>, DiagnosticReportError> {
        self.range()?
            .map(|(source, range)| source.slice(range).map_err(Into::into))
            .transpose()
    }

    /// Derive zero-based byte positions for a diagnostic's half-open range.
    pub fn byte_positions(
        &self,
    ) -> Result<Option<(BytePosition, BytePosition)>, DiagnosticReportError> {
        self.range()?
            .map(|(source, range)| {
                Ok((
                    source.byte_position(range.start())?,
                    source.byte_position(range.end())?,
                ))
            })
            .transpose()
    }

    /// Derive zero-based editor positions in an explicit encoding.
    pub fn positions(
        &self,
        encoding: PositionEncoding,
    ) -> Result<Option<(Position, Position)>, DiagnosticReportError> {
        self.range()?
            .map(|(source, range)| {
                Ok((
                    source.position(range.start(), encoding)?,
                    source.position(range.end(), encoding)?,
                ))
            })
            .transpose()
    }

    /// Render a diagnostic with its source label and checked one-based byte range.
    ///
    /// The displayed range is half-open. Source-less diagnostics omit the
    /// location, as does [`Diagnostic`]'s standalone display implementation.
    pub fn render(&self) -> Result<String, DiagnosticReportError> {
        let diagnostic = self.diagnostic();
        let mut rendered = format!("[{}]", diagnostic.severity);
        if let Some((source, _)) = self.range()? {
            let (start, end) = self
                .byte_positions()?
                .expect("a checked source range has byte positions");
            use std::fmt::Write;
            write!(
                rendered,
                " {}:{}:{}-{}:{}",
                source.label(),
                u64::from(start.line()) + 1,
                u64::from(start.column()) + 1,
                u64::from(end.line()) + 1,
                u64::from(end.column()) + 1
            )
            .expect("writing to String cannot fail");
        }
        if let Some(module) = &diagnostic.module {
            rendered.push(' ');
            rendered.push_str(module);
        }
        if diagnostic.module.is_some() || diagnostic.range.is_some() {
            rendered.push(':');
        }
        rendered.push(' ');
        rendered.push_str(&diagnostic.message);
        Ok(rendered)
    }
}

fn sort_diagnostics(diagnostics: &mut [Diagnostic], sources: &SourceSet) {
    diagnostics.sort_by(|left, right| {
        left.code
            .phase()
            .cmp(right.code.phase())
            .then_with(|| left.code.as_code().cmp(right.code.as_code()))
            .then(left.severity.cmp(&right.severity))
            .then(left.module.cmp(&right.module))
            .then_with(|| compare_ranges(left.range, right.range, sources))
            .then(left.message.cmp(&right.message))
    });
}

fn compare_ranges(
    left: Option<SourceRange>,
    right: Option<SourceRange>,
    sources: &SourceSet,
) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => {
            let left_source = sources.get(left.source());
            let right_source = sources.get(right.source());
            match (left_source, right_source) {
                (Some(left_source), Some(right_source)) => {
                    compare_origins(left_source.origin(), right_source.origin())
                        .then_with(|| left_source.label().cmp(right_source.label()))
                        .then(left.start().cmp(&right.start()))
                        .then(left.end().cmp(&right.end()))
                }
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => left
                    .start()
                    .cmp(&right.start())
                    .then(left.end().cmp(&right.end())),
            }
        }
    }
}

fn compare_origins(left: &SourceOrigin, right: &SourceOrigin) -> Ordering {
    fn rank(origin: &SourceOrigin) -> u8 {
        match origin {
            SourceOrigin::File { .. } => 0,
            SourceOrigin::Embedded { .. } => 1,
            SourceOrigin::Memory { .. } => 2,
            SourceOrigin::Custom { .. } => 3,
        }
    }

    rank(left)
        .cmp(&rank(right))
        .then_with(|| match (left, right) {
            (SourceOrigin::File { path: left }, SourceOrigin::File { path: right }) => {
                left.cmp(right)
            }
            (
                SourceOrigin::Embedded { identity: left },
                SourceOrigin::Embedded { identity: right },
            )
            | (
                SourceOrigin::Memory { identity: left },
                SourceOrigin::Memory { identity: right },
            ) => left.cmp(right),
            (
                SourceOrigin::Custom {
                    provider: left_provider,
                    identity: left_identity,
                },
                SourceOrigin::Custom {
                    provider: right_provider,
                    identity: right_identity,
                },
            ) => left_provider
                .cmp(right_provider)
                .then(left_identity.cmp(right_identity)),
            _ => Ordering::Equal,
        })
}

/// Failure to resolve or convert a source location retained by a report.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DiagnosticReportError {
    /// The diagnostic names a source outside the report's retained source set.
    #[error("source {0} is not retained by this diagnostic report")]
    SourceNotRetained(SourceId),
    /// The retained source rejected the diagnostic's range.
    #[error(transparent)]
    Range(#[from] SourceRangeError),
    /// The retained source rejected a requested position conversion.
    #[error(transparent)]
    Position(#[from] PositionError),
}

/// Controls diagnostic collection, presentation, and failure policy.
///
/// This does NOT control resolver behavior.
/// Resolver fallback behavior is controlled by [`ResolverStrictness`](crate::types::ResolverStrictness).
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    /// Which severity levels are reported. See [`ReportingLevel`].
    pub reporting: ReportingLevel,
    /// Diagnostics at this severity or above cause loading to fail.
    pub fail_at: Severity,
    /// Per-code severity overrides (e.g. promote a warning to error).
    ///
    /// Overrides change the severity stored on emitted diagnostics and used by
    /// failure checks. Demoting a diagnostic does not by itself suppress it;
    /// use [`ignore`](Self::ignore) for suppression.
    pub overrides: HashMap<DiagCode, Severity>,
    /// Glob patterns for [`DiagCode`] strings to suppress (supports `*` and `?`).
    pub ignore: Vec<String>,
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        DiagnosticConfig {
            reporting: ReportingLevel::Default,
            fail_at: Severity::Severe,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }
}

impl DiagnosticConfig {
    /// Returns a preset configuration for the given [`ReportingLevel`].
    pub fn for_reporting(level: ReportingLevel) -> Self {
        match level {
            ReportingLevel::Verbose => Self::verbose(),
            ReportingLevel::Default => Self::default(),
            ReportingLevel::Quiet => Self::quiet(),
            ReportingLevel::Silent => Self::silent(),
        }
    }

    /// Verbose preset: report all diagnostics including style and info.
    pub fn verbose() -> Self {
        DiagnosticConfig {
            reporting: ReportingLevel::Verbose,
            fail_at: Severity::Severe,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Quiet preset: report errors and above only.
    pub fn quiet() -> Self {
        DiagnosticConfig {
            reporting: ReportingLevel::Quiet,
            fail_at: Severity::Severe,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Silent preset: suppress all diagnostics. Only fatal errors cause failure.
    pub fn silent() -> Self {
        DiagnosticConfig {
            reporting: ReportingLevel::Silent,
            fail_at: Severity::Fatal,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Returns the configured severity for a diagnostic code.
    ///
    /// This is the severity stored on emitted diagnostics and evaluated by
    /// [`should_fail`](Self::should_fail).
    pub fn effective_severity(&self, code: DiagCode) -> Severity {
        self.overrides
            .get(&code)
            .copied()
            .unwrap_or_else(|| code.severity())
    }

    /// Returns `true` if the diagnostic code matches an [`ignore`](Self::ignore) pattern.
    pub fn is_ignored(&self, code: DiagCode) -> bool {
        let code_str = code.as_code();
        self.ignore
            .iter()
            .any(|pattern| match_glob(pattern, code_str))
    }

    /// Returns `true` if the reporting level collects the given severity.
    ///
    /// Fatal diagnostics are always collected, including in silent mode.
    /// Ignore patterns are a separate policy evaluated by
    /// [`should_collect`](Self::should_collect).
    pub fn should_report(&self, severity: Severity) -> bool {
        severity == Severity::Fatal
            || self
                .max_reported_severity()
                .is_some_and(|max| severity <= max)
    }

    /// Returns `true` if a diagnostic with the given code should be collected.
    ///
    /// Promotions can bring a diagnostic into the configured reporting level,
    /// while demotions do not discard a diagnostic that its default severity
    /// would collect. Effective fatal diagnostics are always collected,
    /// including when ignored or reporting is silent.
    pub fn should_collect(&self, code: DiagCode) -> bool {
        let effective_severity = self.effective_severity(code);

        if effective_severity == Severity::Fatal {
            return true;
        }

        if self.is_ignored(code) {
            return false;
        }

        self.should_report(code.severity()) || self.should_report(effective_severity)
    }

    /// Returns `true` if the given effective severity meets or exceeds the
    /// [`fail_at`](Self::fail_at) threshold.
    pub fn should_fail(&self, severity: Severity) -> bool {
        severity <= self.fail_at
    }

    /// Returns the maximum severity number (least severe) that should be
    /// reported at the current reporting level.
    ///
    /// - Verbose: report all diagnostics (sev 0-6)
    /// - Default: report Minor and above (sev 0-3)
    /// - Quiet: report Error and above (sev 0-2)
    /// - Silent: report nothing (except fatal, handled by caller)
    fn max_reported_severity(&self) -> Option<Severity> {
        match self.reporting {
            ReportingLevel::Verbose => Some(Severity::Info),
            ReportingLevel::Default => Some(Severity::Minor),
            ReportingLevel::Quiet => Some(Severity::Error),
            ReportingLevel::Silent => None,
        }
    }
}

/// Glob matching on diagnostic codes. Supports * and ? wildcards.
/// Diagnostic codes contain no slashes, so * matches any sequence of characters.
fn match_glob(pattern: &str, s: &str) -> bool {
    glob_match(pattern.as_bytes(), s.as_bytes())
}

fn glob_match(pattern: &[u8], s: &[u8]) -> bool {
    let mut pi = 0;
    let mut si = 0;
    let mut star_pi: Option<usize> = None;
    let mut star_si = 0;

    while si < s.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_si = si;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::source::SourceOrigin;

    use super::*;

    #[test]
    fn diagnostic_display() {
        let d = Diagnostic {
            severity: Severity::Error,
            code: DiagCode::ImportNotFound,
            message: "symbol foo not found".to_string(),
            module: Some("IF-MIB".to_string()),
            range: None,
        };
        assert_eq!(d.to_string(), "[error] IF-MIB: symbol foo not found");
    }

    #[test]
    fn diagnostic_display_no_location() {
        let d = Diagnostic {
            severity: Severity::Warning,
            code: DiagCode::ImportUnused,
            message: "unused import".to_string(),
            module: None,
            range: None,
        };
        assert_eq!(d.to_string(), "[warning] unused import");
    }

    #[test]
    fn report_retains_and_renders_checked_full_range() {
        let mut sources = SourceSet::new();
        let source_id = sources
            .insert(
                SourceOrigin::memory("diagnostic-report"),
                "diagnostic-report",
                Arc::from(&b"first\nsecond"[..]),
            )
            .unwrap();
        let range = sources.get(source_id).unwrap().range(8..10).unwrap();
        let diagnostic = Diagnostic {
            severity: Severity::Error,
            code: DiagCode::ParseError,
            message: "precise range".to_string(),
            module: Some("TEST-MIB".to_string()),
            range: Some(range),
        };
        let sources = Arc::new(sources);
        let report = DiagnosticReport::new(vec![diagnostic], Arc::clone(&sources));
        drop(sources);

        let entry = report.get(0).unwrap();
        assert_eq!(entry.slice().unwrap(), Some(&b"co"[..]));
        assert_eq!(
            entry.byte_positions().unwrap(),
            Some((BytePosition::new(1, 2), BytePosition::new(1, 4)))
        );
        assert_eq!(
            entry.render().unwrap(),
            "[error] diagnostic-report:2:3-2:5 TEST-MIB: precise range"
        );
    }

    #[test]
    fn report_rejects_a_range_whose_source_is_not_retained() {
        let mut retained = SourceSet::new();
        retained
            .insert(
                SourceOrigin::memory("retained"),
                "retained",
                Arc::from(&b"retained"[..]),
            )
            .unwrap();
        let mut foreign = SourceSet::new();
        foreign
            .insert(
                SourceOrigin::memory("foreign-first"),
                "foreign-first",
                Arc::from(&b"first"[..]),
            )
            .unwrap();
        let foreign_id = foreign
            .insert(
                SourceOrigin::memory("foreign-second"),
                "foreign-second",
                Arc::from(&b"second"[..]),
            )
            .unwrap();
        let range = foreign.get(foreign_id).unwrap().range(0..1).unwrap();
        let diagnostic = Diagnostic {
            severity: Severity::Error,
            code: DiagCode::ParseError,
            message: "foreign".to_string(),
            module: None,
            range: Some(range),
        };
        let report = DiagnosticReport::new(vec![diagnostic], Arc::new(retained));

        let entry = report.get(0).unwrap();
        assert!(matches!(
            entry.range(),
            Err(DiagnosticReportError::SourceNotRetained(id)) if id == foreign_id
        ));
        assert!(matches!(
            entry.render(),
            Err(DiagnosticReportError::SourceNotRetained(id)) if id == foreign_id
        ));
    }

    #[test]
    fn report_entries_cannot_cross_resolve_aliased_source_ids() {
        fn report(identity: &str, bytes: &'static [u8]) -> DiagnosticReport {
            let mut sources = SourceSet::new();
            let source_id = sources
                .insert(SourceOrigin::memory(identity), identity, Arc::from(bytes))
                .unwrap();
            let range = sources
                .get(source_id)
                .unwrap()
                .range(0..bytes.len())
                .unwrap();
            DiagnosticReport::new(
                vec![Diagnostic {
                    severity: Severity::Error,
                    code: DiagCode::ParseError,
                    message: identity.to_string(),
                    module: None,
                    range: Some(range),
                }],
                Arc::new(sources),
            )
        }

        let first = report("first", b"alpha");
        let second = report("second", b"bravo!");
        let first_entry = first.get(0).unwrap();
        let second_entry = second.get(0).unwrap();

        assert_eq!(
            first_entry.diagnostic().range.unwrap().source(),
            second_entry.diagnostic().range.unwrap().source()
        );
        assert_eq!(first_entry.slice().unwrap(), Some(&b"alpha"[..]));
        assert_eq!(second_entry.slice().unwrap(), Some(&b"bravo!"[..]));
        assert_eq!(first_entry.range().unwrap().unwrap().0.label(), "first");
        assert_eq!(second_entry.range().unwrap().unwrap().0.label(), "second");
    }

    #[test]
    fn canonical_order_uses_stable_source_identity_not_source_id_allocation() {
        fn report(order: [&str; 2]) -> DiagnosticReport {
            let mut sources = SourceSet::new();
            for identity in order {
                sources
                    .insert(
                        SourceOrigin::memory(identity),
                        identity,
                        Arc::from(&b"x"[..]),
                    )
                    .unwrap();
            }
            let diagnostics = sources
                .iter()
                .map(|source| Diagnostic {
                    severity: Severity::Error,
                    code: DiagCode::ParseError,
                    message: source.label().to_string(),
                    module: Some("TEST-MIB".to_string()),
                    range: Some(source.range(0..1).unwrap()),
                })
                .collect();
            DiagnosticReport::new(diagnostics, Arc::new(sources))
        }

        let forward = report(["a-source", "b-source"]);
        let reverse = report(["b-source", "a-source"]);
        let labels = |report: &DiagnosticReport| {
            report
                .iter()
                .map(|entry| entry.range().unwrap().unwrap().0.label().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(labels(&forward), vec!["a-source", "b-source"]);
        assert_eq!(labels(&reverse), labels(&forward));
    }

    #[test]
    fn canonical_order_is_deterministic_for_source_less_diagnostics() {
        let diagnostic = |message: &str| Diagnostic {
            severity: Severity::Error,
            code: DiagCode::ParseError,
            message: message.to_string(),
            module: None,
            range: None,
        };
        let report = DiagnosticReport::new(
            vec![diagnostic("second"), diagnostic("first")],
            Arc::new(SourceSet::new()),
        );
        assert_eq!(
            report
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.message.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
    }

    #[test]
    fn glob_matching() {
        assert!(match_glob("identifier-*", "identifier-underscore"));
        assert!(match_glob("identifier-*", "identifier-length-32"));
        assert!(!match_glob("identifier-*", "import-not-found"));
        assert!(match_glob("*", "anything"));
        assert!(match_glob("exact-match", "exact-match"));
        assert!(!match_glob("exact-match", "exact-mismatch"));
    }

    #[test]
    fn should_report_respects_level() {
        let config = DiagnosticConfig::default();
        // Default reports Minor and above (sev 0-3)
        assert!(config.should_report(Severity::Error));
        assert!(config.should_report(Severity::Minor));
        assert!(!config.should_report(Severity::Style));
    }

    #[test]
    fn should_report_silent() {
        let config = DiagnosticConfig::silent();
        // Silent reports nothing except fatal
        assert!(config.should_report(Severity::Fatal));
        assert!(!config.should_report(Severity::Error));
        assert!(!config.should_report(Severity::Style));
    }

    #[test]
    fn should_report_verbose() {
        let config = DiagnosticConfig::verbose();
        // Verbose reports everything
        assert!(config.should_report(Severity::Error));
        assert!(config.should_report(Severity::Style));
    }

    #[test]
    fn effective_severity_applies_override() {
        let mut config = DiagnosticConfig::default();
        config
            .overrides
            .insert(DiagCode::MacroNotImported, Severity::Severe);

        assert_eq!(
            config.effective_severity(DiagCode::MacroNotImported),
            Severity::Severe
        );
        assert_eq!(
            config.effective_severity(DiagCode::ParseError),
            Severity::Error
        );
    }

    #[test]
    fn promotion_affects_collection() {
        let mut config = DiagnosticConfig::default();
        config
            .overrides
            .insert(DiagCode::IdentifierUnderscore, Severity::Minor);

        assert!(config.should_collect(DiagCode::IdentifierUnderscore));
    }

    #[test]
    fn demotion_does_not_discard_collected_diagnostic() {
        let mut config = DiagnosticConfig::quiet();
        config
            .overrides
            .insert(DiagCode::ParseError, Severity::Info);

        assert!(config.should_collect(DiagCode::ParseError));
    }

    #[test]
    fn ignore_suppresses_nonfatal_diagnostic() {
        let mut config = DiagnosticConfig::verbose();
        config.ignore.push("parse-*".to_string());

        assert!(config.is_ignored(DiagCode::ParseError));
        assert!(!config.should_collect(DiagCode::ParseError));
    }

    #[test]
    fn effective_fatal_is_always_collected() {
        let mut config = DiagnosticConfig::silent();
        config
            .overrides
            .insert(DiagCode::IdentifierUnderscore, Severity::Fatal);
        config.ignore.push("identifier-*".to_string());

        assert!(config.is_ignored(DiagCode::IdentifierUnderscore));
        assert!(config.should_collect(DiagCode::IdentifierUnderscore));
    }

    #[test]
    fn should_fail_threshold() {
        let config = DiagnosticConfig::default();
        assert!(config.should_fail(Severity::Fatal));
        assert!(config.should_fail(Severity::Severe));
        assert!(!config.should_fail(Severity::Error));
    }

    #[test]
    fn for_reporting_presets() {
        let verbose = DiagnosticConfig::for_reporting(ReportingLevel::Verbose);
        assert!(matches!(verbose.reporting, ReportingLevel::Verbose));

        let silent = DiagnosticConfig::for_reporting(ReportingLevel::Silent);
        assert!(matches!(silent.reporting, ReportingLevel::Silent));
        assert!(matches!(silent.fail_at, Severity::Fatal));
    }
}
