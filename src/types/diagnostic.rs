use std::fmt;

use super::{DiagCode, Severity, StrictnessLevel};

/// Represents an issue found during parsing or resolution.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    pub code: DiagCode,
    pub message: String,
    pub module: String,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.severity)?;
        write!(f, " ")?;
        if !self.module.is_empty() {
            write!(f, "{}", self.module)?;
            if self.line > 0 {
                write!(f, ":{}", self.line)?;
                if self.column > 0 {
                    write!(f, ":{}", self.column)?;
                }
            }
            write!(f, ": ")?;
        }
        write!(f, "{}", self.message)
    }
}

/// Controls strictness and diagnostic filtering.
#[derive(Debug, Clone)]
pub struct DiagnosticConfig {
    pub level: StrictnessLevel,
    pub fail_at: Severity,
    pub overrides: std::collections::HashMap<String, Severity>,
    pub ignore: Vec<String>,
}

impl Default for DiagnosticConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

impl DiagnosticConfig {
    /// Returns the diagnostic configuration preset for the given strictness level.
    pub fn for_level(level: StrictnessLevel) -> Self {
        match level {
            StrictnessLevel::Strict => Self::strict_config(),
            StrictnessLevel::Normal => Self::default_config(),
            StrictnessLevel::Permissive => Self::permissive_config(),
            StrictnessLevel::Silent => Self::silent_config(),
        }
    }

    /// Default diagnostic configuration (Normal strictness).
    pub fn default_config() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Normal,
            fail_at: Severity::Severe,
            overrides: std::collections::HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Strict configuration for RFC compliance checking.
    pub fn strict_config() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Strict,
            fail_at: Severity::Severe,
            overrides: std::collections::HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Permissive configuration for legacy/vendor MIBs.
    pub fn permissive_config() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Permissive,
            fail_at: Severity::Fatal,
            overrides: std::collections::HashMap::new(),
            ignore: vec![
                "identifier-underscore".to_string(),
                "identifier-length-32".to_string(),
                "bad-identifier-case".to_string(),
            ],
        }
    }

    /// Silent configuration that suppresses all diagnostics.
    pub fn silent_config() -> Self {
        DiagnosticConfig {
            level: StrictnessLevel::Silent,
            fail_at: Severity::Fatal,
            overrides: std::collections::HashMap::new(),
            ignore: Vec::new(),
        }
    }

    /// Returns true if a diagnostic with the given code and severity should be reported.
    pub fn should_report(&self, code: DiagCode, sev: Severity) -> bool {
        let effective_sev = self
            .overrides
            .get(code.as_code())
            .copied()
            .unwrap_or(sev);

        // Fatal diagnostics are always reported.
        if effective_sev.at_least(Severity::Fatal) {
            return true;
        }

        // Check ignore list.
        let code_str = code.as_code();
        if self.ignore.iter().any(|pattern| match_glob(pattern, code_str)) {
            return false;
        }

        (effective_sev as i32) <= self.max_reported_severity()
    }

    /// Returns true if a diagnostic with the given severity should cause loading to fail.
    pub fn should_fail(&self, sev: Severity) -> bool {
        sev.at_least(self.fail_at)
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

    fn max_reported_severity(&self) -> i32 {
        if self.level >= StrictnessLevel::Strict {
            Severity::Info as i32
        } else if self.level >= StrictnessLevel::Normal {
            Severity::Minor as i32
        } else if self.level >= StrictnessLevel::Permissive {
            Severity::Warning as i32
        } else {
            -1 // Silent: report nothing (fatal handled above)
        }
    }
}

/// Glob matching on diagnostic codes. Supports *, ?, and [] character classes.
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
            module: "IF-MIB".to_string(),
            line: 42,
            column: 5,
        };
        assert_eq!(d.to_string(), "[error] IF-MIB:42:5: symbol foo not found");
    }

    #[test]
    fn diagnostic_display_no_location() {
        let d = Diagnostic {
            severity: Severity::Warning,
            code: DiagCode::ImportUnused,
            message: "unused import".to_string(),
            module: String::new(),
            line: 0,
            column: 0,
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
        let config = DiagnosticConfig::default_config();
        // Normal reports Minor and above (sev 0-3)
        assert!(config.should_report(DiagCode::ParseError, Severity::Error));
        assert!(config.should_report(DiagCode::MacroNotImported, Severity::Minor));
        assert!(!config.should_report(DiagCode::IdentifierUnderscore, Severity::Style));
    }

    #[test]
    fn should_report_ignores() {
        let config = DiagnosticConfig::permissive_config();
        assert!(
            !config.should_report(DiagCode::IdentifierUnderscore, Severity::Style)
        );
    }

    #[test]
    fn should_fail_threshold() {
        let config = DiagnosticConfig::default_config();
        assert!(config.should_fail(Severity::Fatal));
        assert!(config.should_fail(Severity::Severe));
        assert!(!config.should_fail(Severity::Error));
    }
}
