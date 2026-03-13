//! Diagnostic reporting and configuration.
//!
//! [`Diagnostic`] represents a single issue found during parsing or resolution.
//! [`DiagnosticConfig`] controls which diagnostics are reported and which
//! severities cause loading to fail, with preset configurations for common
//! use cases.

use std::collections::HashMap;
use std::fmt;

use super::{DiagCode, ReportingLevel, Severity};

/// An issue found during parsing or resolution.
///
/// Created from [`SpanDiagnostic`](super::SpanDiagnostic) during lowering, or
/// directly by the resolver. Use [`DiagnosticConfig::should_report`] to filter
/// which diagnostics to display.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    /// Severity of this diagnostic.
    pub severity: Severity,
    /// Diagnostic code identifying the issue category.
    pub code: DiagCode,
    /// Human-readable description of the issue.
    pub message: String,
    /// Module name where the issue was found, if applicable.
    pub module: Option<String>,
    /// 1-based source line number, if available.
    pub line: Option<usize>,
    /// 1-based source column number, if available.
    pub column: Option<usize>,
}

impl fmt::Display for Diagnostic {
    /// Formats as `[severity] module:line:col: message`, omitting location fields when absent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.severity)?;
        if let Some(module) = &self.module {
            write!(f, " {module}")?;
            if let Some(line) = self.line {
                write!(f, ":{line}")?;
                if let Some(col) = self.column {
                    write!(f, ":{col}")?;
                }
            }
            write!(f, ":")?;
        }
        write!(f, " {}", self.message)
    }
}

/// Controls diagnostic reporting and failure policy.
///
/// This is purely about reporting. It does NOT control resolver behavior.
/// Resolver fallback behavior is controlled by [`ResolverStrictness`](crate::types::ResolverStrictness).
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    /// Which severity levels are reported. See [`ReportingLevel`].
    pub reporting: ReportingLevel,
    /// Diagnostics at this severity or above cause loading to fail.
    pub fail_at: Severity,
    /// Per-code severity overrides (e.g. promote a warning to error).
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

    /// Returns `true` if a diagnostic with the given code should be reported
    /// at the current reporting level, accounting for overrides and ignore patterns.
    pub fn should_report(&self, code: DiagCode) -> bool {
        let default_sev = code.severity();
        let effective_sev = self.overrides.get(&code).copied().unwrap_or(default_sev);

        // Fatal diagnostics are always reported.
        if effective_sev <= Severity::Fatal {
            return true;
        }

        // Check ignore list.
        let code_str = code.as_code();
        if self
            .ignore
            .iter()
            .any(|pattern| match_glob(pattern, code_str))
        {
            return false;
        }

        match self.max_reported_severity() {
            Some(max) => effective_sev <= max,
            None => false,
        }
    }

    /// Returns `true` if the given severity meets or exceeds the [`fail_at`](Self::fail_at) threshold.
    pub fn should_fail(&self, sev: Severity) -> bool {
        sev <= self.fail_at
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
    use super::*;

    #[test]
    fn diagnostic_display() {
        let d = Diagnostic {
            severity: Severity::Error,
            code: DiagCode::ImportNotFound,
            message: "symbol foo not found".to_string(),
            module: Some("IF-MIB".to_string()),
            line: Some(42),
            column: Some(5),
        };
        assert_eq!(d.to_string(), "[error] IF-MIB:42:5: symbol foo not found");
    }

    #[test]
    fn diagnostic_display_no_location() {
        let d = Diagnostic {
            severity: Severity::Warning,
            code: DiagCode::ImportUnused,
            message: "unused import".to_string(),
            module: None,
            line: None,
            column: None,
        };
        assert_eq!(d.to_string(), "[warning] unused import");
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
        assert!(config.should_report(DiagCode::ParseError));
        assert!(config.should_report(DiagCode::MacroNotImported));
        assert!(!config.should_report(DiagCode::IdentifierUnderscore));
    }

    #[test]
    fn should_report_silent() {
        let config = DiagnosticConfig::silent();
        // Silent reports nothing except fatal
        assert!(!config.should_report(DiagCode::ImportNotFound));
        assert!(!config.should_report(DiagCode::IdentifierUnderscore));
    }

    #[test]
    fn should_report_verbose() {
        let config = DiagnosticConfig::verbose();
        // Verbose reports everything
        assert!(config.should_report(DiagCode::ParseError));
        assert!(config.should_report(DiagCode::IdentifierUnderscore));
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
