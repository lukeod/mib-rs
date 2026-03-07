use std::collections::HashMap;
use std::fmt;

use super::{DiagCode, Severity, StrictnessLevel};

/// Represents an issue found during parsing or resolution.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: DiagCode,
    pub message: String,
    pub module: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl fmt::Display for Diagnostic {
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

/// Controls strictness and diagnostic filtering.
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    pub level: StrictnessLevel,
    pub fail_at: Severity,
    pub overrides: HashMap<DiagCode, Severity>,
    pub ignore: Vec<String>,
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Normal,
            fail_at: Severity::Severe,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }
}

impl DiagnosticConfig {
    /// Returns the diagnostic configuration preset for the given strictness level.
    pub fn for_level(level: StrictnessLevel) -> Self {
        match level {
            StrictnessLevel::Strict => Self::strict(),
            StrictnessLevel::Normal => Self::default(),
            StrictnessLevel::Permissive => Self::permissive(),
            StrictnessLevel::Silent => Self::silent(),
        }
    }

    /// Strict configuration for RFC compliance checking.
    pub fn strict() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Strict,
            fail_at: Severity::Severe,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Permissive configuration for legacy/vendor MIBs.
    pub fn permissive() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Permissive,
            fail_at: Severity::Fatal,
            overrides: HashMap::new(),
            ignore: vec![
                "identifier-underscore".to_string(),
                "identifier-length-32".to_string(),
                "bad-identifier-case".to_string(),
            ],
        }
    }

    /// Silent configuration that suppresses all diagnostics.
    pub fn silent() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Silent,
            fail_at: Severity::Fatal,
            overrides: HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Returns true if a diagnostic with the given code should be reported.
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

    /// Returns true if a diagnostic with the given severity should cause loading to fail.
    pub fn should_fail(&self, sev: Severity) -> bool {
        sev <= self.fail_at
    }

    /// Returns true if strict RFC compliance is required.
    pub fn is_strict(&self) -> bool {
        self.level > StrictnessLevel::Normal
    }

    /// Returns true if safe fallback strategies should be used.
    pub fn allow_safe_fallbacks(&self) -> bool {
        self.level <= StrictnessLevel::Normal
    }

    /// Returns true if best-guess fallback strategies should be used.
    pub fn allow_best_guess_fallbacks(&self) -> bool {
        self.level <= StrictnessLevel::Permissive
    }

    fn max_reported_severity(&self) -> Option<Severity> {
        match self.level {
            l if l >= StrictnessLevel::Strict => Some(Severity::Info),
            l if l >= StrictnessLevel::Normal => Some(Severity::Minor),
            l if l >= StrictnessLevel::Permissive => Some(Severity::Warning),
            _ => None, // Silent: report nothing (fatal handled above)
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
    let mut star_pi = usize::MAX;
    let mut star_si = 0;

    while si < s.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_si = si;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
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
        // Normal reports Minor and above (sev 0-3)
        assert!(config.should_report(DiagCode::ParseError));
        assert!(config.should_report(DiagCode::MacroNotImported));
        assert!(!config.should_report(DiagCode::IdentifierUnderscore));
    }

    #[test]
    fn should_report_ignores() {
        let config = DiagnosticConfig::permissive();
        assert!(!config.should_report(DiagCode::IdentifierUnderscore));
    }

    #[test]
    fn should_fail_threshold() {
        let config = DiagnosticConfig::default();
        assert!(config.should_fail(Severity::Fatal));
        assert!(config.should_fail(Severity::Severe));
        assert!(!config.should_fail(Severity::Error));
    }
}
