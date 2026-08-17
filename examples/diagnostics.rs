//! Resolver strictness, diagnostic reporting, severity overrides, filtering,
//! and failure thresholds.

use mib_rs::{
    DiagCode, DiagnosticConfig, DiagnosticEntry, LoadError, Loader, Mib, ReportingLevel,
    ResolverStrictness, Severity,
};

fn make_source() -> Box<dyn mib_rs::Source> {
    mib_rs::source::memory(
        "DIAG-EXAMPLE-MIB",
        br#"DIAG-EXAMPLE-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI;

diagMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "MIB for diagnostics examples."
    ::= { enterprises 99997 }

diagValue OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A display string whose type is not imported."
    ::= { diagMib 1 }

END
"#,
    )
}

fn load_with(
    strictness: ResolverStrictness,
    config: DiagnosticConfig,
) -> Result<Mib, mib_rs::LoadError> {
    Loader::new()
        .source(make_source())
        .modules(["DIAG-EXAMPLE-MIB"])
        .resolver_strictness(strictness)
        .diagnostic_config(config)
        .load()
}

fn print_summary(mib: &Mib) {
    println!("  Has errors: {}", mib.has_errors());
    let report = mib.diagnostic_report();
    println!("  Diagnostics: {}", report.len());
    for entry in report.iter() {
        println!("    {}", render(entry));
    }

    println!("  Unresolved references: {}", mib.unresolved().len());
    for unresolved in mib.unresolved() {
        println!("    {unresolved:?}");
    }
}

fn render(entry: DiagnosticEntry<'_>) -> String {
    entry
        .render()
        .unwrap_or_else(|error| format!("{} [location unavailable: {error}]", entry.diagnostic()))
}

fn main() {
    // DisplayString is intentionally not imported. Normal and Permissive
    // recover it from a well-known base module; Strict leaves it unresolved.
    // The fixture also omits REVISION and imports an unused Integer32 so the
    // reporting examples have minor and style diagnostics to configure.
    for strictness in [
        ResolverStrictness::Normal,
        ResolverStrictness::Strict,
        ResolverStrictness::Permissive,
    ] {
        println!("=== {strictness:?} resolver ===");
        let mib = load_with(strictness, DiagnosticConfig::default()).expect("should load");
        print_summary(&mib);
        println!();
    }

    // Reporting presets change which diagnostics are retained, not how names
    // are resolved.
    for (name, config) in [
        ("Verbose", DiagnosticConfig::verbose()),
        ("Quiet", DiagnosticConfig::quiet()),
        ("Silent", DiagnosticConfig::silent()),
    ] {
        println!("=== {name} reporting ===");
        let mib = load_with(ResolverStrictness::Normal, config).expect("should load");
        print_summary(&mib);
        println!();
    }

    // Promote one diagnostic and inspect the effective severity stored on it.
    println!("=== Severity override ===");
    let mut config = DiagnosticConfig::for_reporting(ReportingLevel::Verbose);
    config
        .overrides
        .insert(DiagCode::ImportUnused, Severity::Minor);
    let mib = load_with(ResolverStrictness::Normal, config).expect("should load");
    for diagnostic in mib.diagnostics() {
        println!(
            "  [{}] {:?}: {}",
            diagnostic.code, diagnostic.severity, diagnostic.message
        );
    }

    // Ignore patterns suppress matching diagnostic codes.
    println!("\n=== Diagnostic filtering ===");
    let mut config = DiagnosticConfig::for_reporting(ReportingLevel::Verbose);
    config.ignore.push("import-*".to_string());
    let mib = load_with(ResolverStrictness::Normal, config).expect("should load");
    print_summary(&mib);

    // fail_at changes which retained severities make load() return an error.
    println!("\n=== Failure threshold ===");
    let config = DiagnosticConfig {
        fail_at: Severity::Minor,
        ..DiagnosticConfig::default()
    };
    match load_with(ResolverStrictness::Normal, config) {
        Ok(mib) => println!("  Loaded with {} diagnostics", mib.diagnostics().len()),
        Err(LoadError::DiagnosticThreshold { report }) => {
            println!("  Load failed with {} diagnostics:", report.len());
            for entry in report.iter() {
                println!("    {}", render(entry));
            }
        }
        Err(error) => println!("  Load failed: {error}"),
    }

    println!("\n=== Diagnostic fields ===");
    let mib =
        load_with(ResolverStrictness::Normal, DiagnosticConfig::verbose()).expect("should load");
    let report = mib.diagnostic_report();
    for entry in report.iter() {
        let diagnostic = entry.diagnostic();
        println!("  Severity: {:?}", diagnostic.severity);
        println!("  Code:     {}", diagnostic.code);
        println!("  Message:  {}", diagnostic.message);
        if let Some(module) = &diagnostic.module {
            println!("  Module:   {module}");
        }
        match entry.range() {
            Ok(Some((source, range))) => {
                let (start, end) = entry
                    .byte_positions()
                    .expect("retained diagnostic range should convert")
                    .expect("ranged diagnostic should have positions");
                println!("  Source:   {} ({:?})", source.label(), source.origin());
                println!(
                    "  Range:    bytes {}..{}, {}:{}-{}:{}",
                    range.start(),
                    range.end(),
                    u64::from(start.line()) + 1,
                    u64::from(start.column()) + 1,
                    u64::from(end.line()) + 1,
                    u64::from(end.column()) + 1
                );
            }
            Ok(None) => println!("  Location: source-less"),
            Err(error) => println!("  Location unavailable: {error}"),
        }
        println!();
    }
}
