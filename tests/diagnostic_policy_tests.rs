use mib_rs::{DiagCode, DiagnosticConfig, LoadError, Loader, Severity};

const SOURCE: &[u8] = br#"DIAGNOSTIC-POLICY-MIB { 01 } DEFINITIONS ::= BEGIN
IMPORTS
    Integer32
        FROM SNMPv2-SMI;

bad_name OBJECT IDENTIFIER ::= { iso 99999 }
END
"#;

fn source() -> Box<dyn mib_rs::Source> {
    mib_rs::source::memory("DIAGNOSTIC-POLICY-MIB", SOURCE)
}

fn config_with_override(code: DiagCode, severity: Severity) -> DiagnosticConfig {
    let mut config = DiagnosticConfig::default();
    config.overrides.insert(code, severity);
    config
}

#[test]
fn promoted_diagnostic_uses_effective_severity_and_fails_load() {
    let config = config_with_override(DiagCode::NumberLeadingZero, Severity::Severe);

    let result = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(config)
        .load();

    assert!(matches!(result, Err(LoadError::DiagnosticThreshold { .. })));
}

fn diagnostic_key(
    diagnostic: &mib_rs::Diagnostic,
) -> (
    &'static str,
    &'static str,
    Severity,
    Option<&str>,
    Option<usize>,
    Option<usize>,
    &str,
) {
    (
        diagnostic.code.phase(),
        diagnostic.code.as_code(),
        diagnostic.severity,
        diagnostic.module.as_deref(),
        diagnostic.line,
        diagnostic.column,
        &diagnostic.message,
    )
}

#[test]
fn threshold_error_retains_all_diagnostics_in_canonical_order() {
    let mut failing_config = DiagnosticConfig::verbose();
    failing_config
        .overrides
        .insert(DiagCode::NumberLeadingZero, Severity::Severe);

    let mut non_failing_config = failing_config.clone();
    non_failing_config.fail_at = Severity::Fatal;
    let expected_mib = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(non_failing_config)
        .load()
        .expect("fatal-only threshold should permit this MIB");
    let mut expected_keys: Vec<_> = expected_mib
        .diagnostics()
        .iter()
        .map(diagnostic_key)
        .collect();
    expected_keys.sort();

    let error = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(failing_config.clone())
        .load()
        .expect_err("promoted diagnostic should fail loading");
    let LoadError::DiagnosticThreshold { diagnostics } = error else {
        panic!("expected diagnostic threshold error");
    };
    let actual_keys: Vec<_> = diagnostics.iter().map(diagnostic_key).collect();

    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| !failing_config.should_fail(diagnostic.severity))
    );
    assert_eq!(actual_keys, expected_keys);
}

#[test]
fn demoted_diagnostic_is_retained_with_effective_severity() {
    let config = config_with_override(DiagCode::NumberLeadingZero, Severity::Info);

    let mib = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(config)
        .load()
        .expect("demoted diagnostic should not fail loading");

    let diagnostic = mib
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == DiagCode::NumberLeadingZero)
        .expect("demotion should not remove a normally collected diagnostic");
    assert_eq!(diagnostic.severity, Severity::Info);
}

#[test]
fn lowering_recomputes_parser_diagnostic_severity_with_its_own_config() {
    let parser_config = DiagnosticConfig::default();
    let mut modules = mib_rs::parser::parse(SOURCE, &parser_config);
    let ast_module = modules.pop().expect("expected parsed module");
    let parsed_diagnostic = ast_module
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == DiagCode::NumberLeadingZero)
        .expect("expected parser diagnostic");
    assert_eq!(parsed_diagnostic.severity, Severity::Minor);

    let lower_config = config_with_override(DiagCode::NumberLeadingZero, Severity::Severe);
    let ir_module = mib_rs::lower::lower(ast_module, SOURCE, &lower_config);
    let lowered_diagnostic = ir_module
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == DiagCode::NumberLeadingZero)
        .expect("expected lowered parser diagnostic");
    assert_eq!(lowered_diagnostic.severity, Severity::Severe);
}

#[test]
fn emitters_store_effective_severity_across_pipeline_phases() {
    let mut config = DiagnosticConfig::verbose();
    config.fail_at = Severity::Fatal;
    for code in [
        DiagCode::NumberLeadingZero,
        DiagCode::IdentifierUnderscore,
        DiagCode::MissingModuleIdentity,
        DiagCode::ImportUnused,
    ] {
        config.overrides.insert(code, Severity::Info);
    }

    let mib = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(config)
        .load()
        .expect("demoted diagnostics should not fail loading");

    for code in [
        DiagCode::NumberLeadingZero,
        DiagCode::IdentifierUnderscore,
        DiagCode::MissingModuleIdentity,
        DiagCode::ImportUnused,
    ] {
        let diagnostic = mib
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("expected {code} diagnostic"));
        assert_eq!(diagnostic.severity, Severity::Info, "code {code}");
    }
}

#[test]
fn parse_error_override_is_applied_to_recovered_errors() {
    let mut config = DiagnosticConfig::verbose();
    config.fail_at = Severity::Fatal;
    config
        .overrides
        .insert(DiagCode::ParseError, Severity::Info);

    let mib = Loader::new()
        .source(mib_rs::source::memory(
            "PARSE-ERROR-MIB",
            b"PARSE-ERROR-MIB DEFINITIONS ::= BEGIN unexpected END".as_slice(),
        ))
        .modules(["PARSE-ERROR-MIB"])
        .diagnostic_config(config)
        .load()
        .expect("demoted parse error should not fail loading");

    let diagnostic = mib
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == DiagCode::ParseError)
        .expect("expected recovered parse error");
    assert_eq!(diagnostic.severity, Severity::Info);
}

#[test]
fn ignored_diagnostic_is_not_collected() {
    let mut config = DiagnosticConfig::verbose();
    config.ignore.push("number-leading-*".to_string());

    let mib = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(config)
        .load()
        .expect("ignored diagnostic should not fail loading");

    assert!(
        mib.diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code != DiagCode::NumberLeadingZero)
    );
}

#[test]
fn fatal_override_is_collected_despite_silent_reporting_and_ignore() {
    let mut config = DiagnosticConfig::silent();
    config
        .overrides
        .insert(DiagCode::NumberLeadingZero, Severity::Fatal);
    config.ignore.push("number-leading-*".to_string());
    config.fail_at = Severity::Fatal;

    let result = Loader::new()
        .source(source())
        .modules(["DIAGNOSTIC-POLICY-MIB"])
        .diagnostic_config(config)
        .load();

    assert!(matches!(result, Err(LoadError::DiagnosticThreshold { .. })));
}
