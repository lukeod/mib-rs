#![cfg(feature = "cli")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

const DEFINER_MIB: &str = r#"DEFINER-MIB DEFINITIONS ::= BEGIN
definerRoot OBJECT IDENTIFIER ::= { iso 424280 }
forwardedSymbol OBJECT IDENTIFIER ::= { definerRoot 1 }
END
"#;

const FORWARDER_MIB: &str = r#"FORWARDER-MIB DEFINITIONS ::= BEGIN
IMPORTS forwardedSymbol FROM DEFINER-MIB;
END
"#;

const SCOPE_MIB: &str = r#"SCOPE-MIB DEFINITIONS ::= BEGIN
IMPORTS forwardedSymbol FROM FORWARDER-MIB;
scopeRoot OBJECT IDENTIFIER ::= { iso 424281 }
scopeChild OBJECT IDENTIFIER ::= { forwardedSymbol 1 }
brokenChild OBJECT IDENTIFIER ::= { missingSymbol 1 }
END
"#;

const ALPHA_MIB: &str = r#"ALPHA-MIB DEFINITIONS ::= BEGIN
duplicateSymbol OBJECT IDENTIFIER ::= { iso 424282 }
END
"#;

const ZETA_MIB: &str = r#"ZETA-MIB DEFINITIONS ::= BEGIN
duplicateSymbol OBJECT IDENTIFIER ::= { iso 424283 }
END
"#;

const GLOBAL_MIB: &str = r#"GLOBAL-MIB DEFINITIONS ::= BEGIN
globalOnly OBJECT IDENTIFIER ::= { iso 424284 }
globalObject OBJECT-TYPE
    SYNTAX INTEGER
    ACCESS read-only
    STATUS mandatory
    ::= { globalOnly 1 }
END
"#;

const COLLISION_MIB: &str = r#"COLLISION-MIB DEFINITIONS ::= BEGIN
collisionName ::= INTEGER
collisionName OBJECT IDENTIFIER ::= { iso 424285 }
END
"#;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mib-rs-cli-trace-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        for (name, source) in [
            ("DEFINER-MIB", DEFINER_MIB),
            ("FORWARDER-MIB", FORWARDER_MIB),
            ("SCOPE-MIB", SCOPE_MIB),
            ("ALPHA-MIB", ALPHA_MIB),
            ("ZETA-MIB", ZETA_MIB),
            ("GLOBAL-MIB", GLOBAL_MIB),
            ("COLLISION-MIB", COLLISION_MIB),
        ] {
            fs::write(path.join(format!("{name}.mib")), source).expect("write trace fixture");
        }
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_trace(directory: &TestDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mib-rs"))
        .arg("--path")
        .arg(directory.path())
        .arg("trace")
        .args(args)
        .output()
        .expect("run mib-rs trace")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("UTF-8 stdout")
}

#[test]
fn forwarded_import_trace_retains_exact_path_and_qualified_scope() {
    let directory = TestDir::new();
    let unqualified = run_trace(
        &directory,
        &[
            "--domain",
            "oid",
            "--module",
            "SCOPE-MIB",
            "forwardedSymbol",
        ],
    );
    assert_eq!(unqualified.status.code(), Some(0));
    assert!(unqualified.stderr.is_empty());
    let unqualified_stdout = stdout(&unqualified);
    assert!(unqualified_stdout.contains("Domain: oid"));
    assert!(unqualified_stdout.contains("Module scope: SCOPE-MIB [source "));
    assert!(unqualified_stdout.contains("mode: forwarded"));
    assert!(unqualified_stdout.contains("FORWARDER-MIB [source "));
    assert!(unqualified_stdout.contains("DEFINER-MIB [source "));
    assert!(unqualified_stdout.contains("resolved, selected"));
    assert!(
        unqualified_stdout.contains("DEFINER-MIB::forwardedSymbol (node, via forwarded import)")
    );

    let qualified = run_trace(
        &directory,
        &["--domain", "oid", "SCOPE-MIB::forwardedSymbol"],
    );
    assert_eq!(qualified.status.code(), Some(0));
    assert!(qualified.stderr.is_empty());
    assert_eq!(
        unqualified_stdout.lines().skip(1).collect::<Vec<_>>(),
        stdout(&qualified).lines().skip(1).collect::<Vec<_>>()
    );
}

#[test]
fn ambiguity_and_missing_symbol_have_deterministic_diagnostic_output() {
    let directory = TestDir::new();
    let ambiguous = run_trace(&directory, &["--domain", "oid", "duplicateSymbol"]);
    assert_eq!(ambiguous.status.code(), Some(1));
    assert!(ambiguous.stderr.is_empty());
    let ambiguous_stdout = stdout(&ambiguous);
    let alpha = ambiguous_stdout
        .find("ALPHA-MIB::duplicateSymbol")
        .expect("alpha candidate");
    let zeta = ambiguous_stdout
        .find("ZETA-MIB::duplicateSymbol")
        .expect("zeta candidate");
    assert!(alpha < zeta, "{ambiguous_stdout}");
    assert!(ambiguous_stdout.contains("Resolved target:\n  (ambiguous)"));
    let repeated = run_trace(&directory, &["--domain", "oid", "duplicateSymbol"]);
    assert_eq!(ambiguous_stdout, stdout(&repeated));

    let missing = run_trace(
        &directory,
        &["--domain", "oid", "--module", "SCOPE-MIB", "missingSymbol"],
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(missing.stderr.is_empty());
    let missing_stdout = stdout(&missing);
    assert!(missing_stdout.contains("Candidates:\n  (none)"));
    assert!(missing_stdout.contains("Resolved target:\n  (not found)"));
    assert!(missing_stdout.contains("[oid] missingSymbol in SCOPE-MIB: unknown_parent"));
}

#[test]
fn strictness_is_applied_by_reference_domain() {
    let directory = TestDir::new();

    for strictness in ["strict", "normal", "permissive"] {
        let oid = run_trace(
            &directory,
            &[
                "--domain",
                "oid",
                "--module",
                "SCOPE-MIB",
                "--strictness",
                strictness,
                "globalOnly",
            ],
        );
        assert_eq!(oid.status.code(), Some(1), "{strictness}: {}", stdout(&oid));
        let oid_stdout = stdout(&oid);
        assert!(oid_stdout.contains("global: disabled"));
        assert!(oid_stdout.contains("Resolved target:\n  (not found)"));
    }

    let member = run_trace(
        &directory,
        &[
            "--domain",
            "group-member",
            "--module",
            "SCOPE-MIB",
            "--strictness",
            "permissive",
            "globalOnly",
        ],
    );
    assert_eq!(member.status.code(), Some(0));
    let member_stdout = stdout(&member);
    assert!(member_stdout.contains("global: enabled"));
    assert!(member_stdout.contains("GLOBAL-MIB::globalOnly (node, via global fallback)"));

    for (domain, symbol, kind) in [
        ("object", "globalObject", "object"),
        ("index", "globalObject", "object"),
        ("conformance", "globalOnly", "node"),
    ] {
        let output = run_trace(
            &directory,
            &[
                "--domain",
                domain,
                "--module",
                "SCOPE-MIB",
                "--strictness",
                "permissive",
                symbol,
            ],
        );
        assert_eq!(output.status.code(), Some(0), "{}", stdout(&output));
        assert!(stdout(&output).contains(&format!(
            "GLOBAL-MIB::{symbol} ({kind}, via global fallback)"
        )));
    }

    let strict_type = run_trace(
        &directory,
        &[
            "--domain",
            "type",
            "--module",
            "SCOPE-MIB",
            "--strictness",
            "strict",
            "Integer32",
        ],
    );
    assert_eq!(strict_type.status.code(), Some(1));
    let normal_type = run_trace(
        &directory,
        &["--domain", "type", "--module", "SCOPE-MIB", "Integer32"],
    );
    assert_eq!(normal_type.status.code(), Some(0));
    assert!(stdout(&normal_type).contains("via constrained fallback"));

    let bare_index = run_trace(
        &directory,
        &["--domain", "index", "--module", "SCOPE-MIB", "Integer32"],
    );
    assert_eq!(bare_index.status.code(), Some(0));
    assert!(stdout(&bare_index).contains("type, via constrained fallback"));

    let notification_node = run_trace(
        &directory,
        &[
            "--domain",
            "notification-object",
            "--module",
            "SCOPE-MIB",
            "--strictness",
            "permissive",
            "globalOnly",
        ],
    );
    assert_eq!(notification_node.status.code(), Some(1));
    assert!(stdout(&notification_node).contains("Resolved target:\n  (not found)"));
}

#[test]
fn kind_collisions_list_every_candidate_and_choose_by_domain() {
    let directory = TestDir::new();
    let type_output = run_trace(
        &directory,
        &[
            "--domain",
            "type",
            "--module",
            "COLLISION-MIB",
            "collisionName",
        ],
    );
    assert_eq!(type_output.status.code(), Some(0));
    let type_stdout = stdout(&type_output);
    assert!(type_stdout.contains("COLLISION-MIB::collisionName (type"));
    assert!(type_stdout.contains("COLLISION-MIB::collisionName (node"));
    assert!(type_stdout.contains("COLLISION-MIB::collisionName (type, via local definition)"));

    let oid_output = run_trace(
        &directory,
        &[
            "--domain",
            "oid",
            "--module",
            "COLLISION-MIB",
            "collisionName",
        ],
    );
    assert_eq!(oid_output.status.code(), Some(0));
    assert!(
        stdout(&oid_output).contains("COLLISION-MIB::collisionName (node, via local definition)")
    );
}

#[test]
fn invalid_or_conflicting_scope_is_an_operational_error() {
    let directory = TestDir::new();
    let conflicting = run_trace(
        &directory,
        &[
            "--domain",
            "oid",
            "--module",
            "GLOBAL-MIB",
            "SCOPE-MIB::scopeRoot",
        ],
    );
    assert_eq!(conflicting.status.code(), Some(2));
    assert!(conflicting.stdout.is_empty());
    assert!(String::from_utf8_lossy(&conflicting.stderr).contains("conflicts with --module"));

    let missing_scope = run_trace(
        &directory,
        &["--domain", "oid", "--module", "ABSENT-MIB", "scopeRoot"],
    );
    assert_eq!(missing_scope.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing_scope.stderr).contains("module scope not found"));
}
