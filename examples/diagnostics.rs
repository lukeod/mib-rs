//! Diagnostic collection, strictness levels, reporting configuration,
//! filtering, and severity overrides.

use mib_rs::{DiagnosticConfig, Loader, ReportingLevel, ResolverStrictness};

/// Create a fresh source for each loader (Source is not Clone).
fn make_source() -> Box<dyn mib_rs::Source> {
    mib_rs::source::memory(
        "DIAG-EXAMPLE-MIB",
        br#"DIAG-EXAMPLE-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    DisplayString, NoSuchThing
        FROM SNMPv2-TC;

diagMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "MIB for diagnostics demo."
    ::= { enterprises 99997 }

diagValue OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A value."
    ::= { diagMib 1 }

END
"#,
    )
}

fn main() {
    // -- Default settings --
    println!("=== Default strictness (Normal) ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .load()
        .expect("should load");

    println!("  Has errors: {}", mib.has_errors());
    println!("  Diagnostics: {}", mib.diagnostics().len());
    for d in mib.diagnostics() {
        println!("    {d}");
    }

    // Unresolved references
    let unresolved = mib.unresolved();
    if !unresolved.is_empty() {
        println!("  Unresolved references: {}", unresolved.len());
        for u in unresolved {
            println!("    {u:?}");
        }
    }

    // -- Strict mode --
    println!("\n=== Strict mode ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .resolver_strictness(ResolverStrictness::Strict)
        .load()
        .expect("should load");

    println!("  Has errors: {}", mib.has_errors());
    println!("  Diagnostics: {}", mib.diagnostics().len());
    for d in mib.diagnostics() {
        println!("    {d}");
    }

    // -- Permissive mode --
    println!("\n=== Permissive mode ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .resolver_strictness(ResolverStrictness::Permissive)
        .load()
        .expect("should load");

    println!("  Has errors: {}", mib.has_errors());
    println!("  Diagnostics: {}", mib.diagnostics().len());

    // -- Reporting levels --
    println!("\n=== Verbose reporting ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .diagnostic_config(DiagnosticConfig::verbose())
        .load()
        .expect("should load");

    println!("  Diagnostics (verbose): {}", mib.diagnostics().len());
    for d in mib.diagnostics() {
        println!("    [{:?}] {}", d.severity, d.message);
    }

    println!("\n=== Quiet reporting ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .diagnostic_config(DiagnosticConfig::quiet())
        .load()
        .expect("should load");

    println!("  Diagnostics (quiet): {}", mib.diagnostics().len());
    for d in mib.diagnostics() {
        println!("    [{:?}] {}", d.severity, d.message);
    }

    println!("\n=== Silent reporting ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("should load");

    println!("  Diagnostics (silent): {}", mib.diagnostics().len());

    // -- Custom diagnostic config --
    println!("\n=== Custom config with overrides ===");
    let mut config = DiagnosticConfig::for_reporting(ReportingLevel::Verbose);
    // Ignore specific diagnostic patterns.
    config.ignore.push("import-*".to_string());
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .diagnostic_config(config)
        .load()
        .expect("should load");

    println!(
        "  Diagnostics (import-* ignored): {}",
        mib.diagnostics().len()
    );
    for d in mib.diagnostics() {
        println!("    [{}] {}", d.code, d.message);
    }

    // -- Diagnostic severity threshold --
    // DiagnosticConfig.fail_at controls what severity causes LoadError::DiagnosticThreshold.
    println!("\n=== Fail-at threshold ===");
    let mut config = DiagnosticConfig::for_reporting(ReportingLevel::Verbose);
    config.fail_at = mib_rs::Severity::Minor;

    let result = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .diagnostic_config(config)
        .load();

    match result {
        Ok(mib) => println!("  Loaded OK, errors={}", mib.has_errors()),
        Err(e) => println!("  Load failed: {e}"),
    }

    // -- Inspecting diagnostic fields --
    println!("\n=== Diagnostic details ===");
    let mib = Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .diagnostic_config(DiagnosticConfig::verbose())
        .load()
        .expect("should load");

    for d in mib.diagnostics() {
        println!("  Severity: {:?}", d.severity);
        println!("  Code:     {}", d.code);
        println!("  Message:  {}", d.message);
        if let Some(ref module) = d.module {
            println!("  Module:   {module}");
        }
        if let Some(line) = d.line {
            print!("  Location: line {line}");
            if let Some(col) = d.column {
                print!(", col {col}");
            }
            println!();
        }
        println!();
    }
}
