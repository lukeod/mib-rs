#![cfg(feature = "cli")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

const A_MIB: &str = r#"A-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    OBJECT-GROUP, MODULE-COMPLIANCE
        FROM SNMPv2-CONF;

aMib MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "Normalize tests"
    CONTACT-INFO "Normalize tests"
    DESCRIPTION "Module A."
    ::= { enterprises 424270 }

aTable OBJECT-TYPE
    SYNTAX SEQUENCE OF AEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Table A."
    ::= { aMib 1 }

aEntry OBJECT-TYPE
    SYNTAX AEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Entry A."
    INDEX { aIndex }
    ::= { aTable 1 }

aIndex OBJECT-TYPE
    SYNTAX Integer32 (1..10)
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Index A."
    ::= { aEntry 1 }

aObjects OBJECT-GROUP
    OBJECTS { aIndex }
    STATUS current
    DESCRIPTION "Objects A."
    ::= { aMib 2 }

aCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "Compliance A."
    MODULE
        MANDATORY-GROUPS { aObjects }
    ::= { aMib 3 }

AEntry ::= SEQUENCE {
    aIndex Integer32
}

END
"#;

const B_MIB: &str = r#"B-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;

bMib MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "Normalize tests"
    CONTACT-INFO "Normalize tests"
    DESCRIPTION "Module B."
    ::= { enterprises 424271 }

bScalar OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Scalar B."
    ::= { bMib 1 }

END
"#;

const ERROR_MIB: &str = r#"ERROR-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;

errorMib MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "Normalize tests"
    CONTACT-INFO "Normalize tests"
    DESCRIPTION "Renderable diagnostic module."
    ::= { enterprises 424274 }

errorScalar OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS write-only
    STATUS current
    DESCRIPTION "Renderable despite invalid SMIv2 access."
    ::= { errorMib 1 }

END
"#;

const Z_REJECTED_MIB: &str = r#"Z-REJECTED-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;

zRejectedMib MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "Normalize tests"
    CONTACT-INFO "Normalize tests"
    DESCRIPTION "Writer preflight rejection module."
    ::= { enterprises 424275 }

zTable OBJECT-TYPE
    SYNTAX SEQUENCE OF ZEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Table."
    ::= { zRejectedMib 1 }

zEntry OBJECT-TYPE
    SYNTAX ZEntry
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Row without INDEX or AUGMENTS."
    ::= { zTable 1 }

zColumn OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Column."
    ::= { zEntry 1 }

ZEntry ::= SEQUENCE {
    zColumn Integer32
}

END
"#;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "mib-rs-cli-normalize-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        fs::write(path.join("A-MIB.mib"), A_MIB).expect("write A-MIB");
        fs::write(path.join("B-MIB.mib"), B_MIB).expect("write B-MIB");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write_module(&self, name: &str, contents: &str) {
        fs::write(self.path().join(format!("{name}.mib")), contents).expect("write test MIB");
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_normalize(directory: &TestDir, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_mib-rs"));
    command
        .arg("--path")
        .arg(directory.path())
        .arg("normalize")
        .args(args)
        .output()
        .expect("run mib-rs normalize")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn stdout_emits_exactly_one_selected_module() {
    let directory = TestDir::new();
    let output = run_normalize(&directory, &["A-MIB"]);
    assert_success(&output);

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(stdout.starts_with("A-MIB DEFINITIONS ::= BEGIN\n"));
    assert!(stdout.ends_with("\nEND\n"));
    assert!(!stdout.contains("B-MIB DEFINITIONS"));
    assert!(stdout.contains("aObjects OBJECT-GROUP"));
    assert!(stdout.contains("AEntry ::= SEQUENCE"));
}

#[test]
fn stdout_emits_renderable_module_and_exits_one_for_error_diagnostic() {
    let directory = TestDir::new();
    directory.write_module("ERROR-MIB", ERROR_MIB);

    let output = run_normalize(&directory, &["ERROR-MIB"]);

    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(stdout.starts_with("ERROR-MIB DEFINITIONS ::= BEGIN\n"));
    assert!(stdout.contains("errorScalar OBJECT-TYPE"));
    assert!(stdout.contains("MAX-ACCESS read-write"), "{stdout}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[error]"), "{stderr}");
    assert!(
        stderr.contains("write-only is no longer allowed in SMIv2"),
        "{stderr}"
    );
}

#[test]
fn stdout_rejects_multiple_selected_modules_without_partial_output() {
    let directory = TestDir::new();
    let output = run_normalize(&directory, &["B-MIB", "A-MIB"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("stdout normalization requires exactly one module")
    );
}

#[test]
fn stdout_rejects_implicit_all_when_multiple_modules_are_available() {
    let directory = TestDir::new();
    let output = run_normalize(&directory, &[]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("stdout normalization selected 2 modules")
    );
}

#[test]
fn writer_controls_apply_to_cli_output() {
    let directory = TestDir::new();
    let output = run_normalize(
        &directory,
        &[
            "--no-descriptions",
            "--no-conformance",
            "--no-sequences",
            "A-MIB",
        ],
    );
    assert_success(&output);

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(!stdout.contains("DESCRIPTION"));
    assert!(!stdout.contains("OBJECT-GROUP"));
    assert!(!stdout.contains("MODULE-COMPLIANCE"));
    assert!(!stdout.contains("::= SEQUENCE {"));
    assert!(stdout.contains("aIndex OBJECT-TYPE"));
}

#[test]
fn output_directory_writes_sorted_module_files_and_replaces_existing_files() {
    let directory = TestDir::new();
    let output_directory = directory.path().join("normalized");
    fs::create_dir(&output_directory).expect("create output directory");
    fs::write(output_directory.join("A-MIB.mib"), "stale").expect("write stale output");

    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
            "B-MIB",
            "A-MIB",
        ],
    );
    assert_success(&output);
    assert!(output.stdout.is_empty());

    let a = fs::read_to_string(output_directory.join("A-MIB.mib")).expect("read A output");
    let b = fs::read_to_string(output_directory.join("B-MIB.mib")).expect("read B output");
    assert!(a.starts_with("A-MIB DEFINITIONS ::= BEGIN\n"));
    assert!(b.starts_with("B-MIB DEFINITIONS ::= BEGIN\n"));
    assert_ne!(a, "stale");
    let mut names = fs::read_dir(&output_directory)
        .expect("read output directory")
        .map(|entry| {
            entry
                .expect("read directory entry")
                .file_name()
                .into_string()
                .expect("UTF-8 filename")
        })
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, ["A-MIB.mib", "B-MIB.mib"]);
}

#[test]
fn output_directory_without_module_arguments_writes_all_user_modules() {
    let directory = TestDir::new();
    let output_directory = directory.path().join("all-normalized");
    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
        ],
    );
    assert_success(&output);
    assert!(output_directory.join("A-MIB.mib").is_file());
    assert!(output_directory.join("B-MIB.mib").is_file());
}

#[test]
fn output_directory_writes_renderable_module_and_exits_one_for_error_diagnostic() {
    let directory = TestDir::new();
    directory.write_module("ERROR-MIB", ERROR_MIB);
    let output_directory = directory.path().join("error-normalized");

    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
            "ERROR-MIB",
        ],
    );

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let normalized = fs::read_to_string(output_directory.join("ERROR-MIB.mib"))
        .expect("read diagnostic module output");
    assert!(normalized.starts_with("ERROR-MIB DEFINITIONS ::= BEGIN\n"));
    assert!(normalized.contains("errorScalar OBJECT-TYPE"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("[error]"), "{stderr}");
    assert!(
        stderr.contains("write-only is no longer allowed in SMIv2"),
        "{stderr}"
    );
}

#[test]
fn writer_rejection_of_later_module_leaves_all_output_files_untouched() {
    let directory = TestDir::new();
    directory.write_module("Z-REJECTED-MIB", Z_REJECTED_MIB);
    let output_directory = directory.path().join("preflight-normalized");
    fs::create_dir(&output_directory).expect("create output directory");
    fs::write(output_directory.join("A-MIB.mib"), "sentinel").expect("preseed earlier output");

    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
            "Z-REJECTED-MIB",
            "A-MIB",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to normalize Z-REJECTED-MIB"));
    assert!(
        stderr.contains("declares a row without INDEX or AUGMENTS"),
        "{stderr}"
    );
    assert!(!stderr.contains("failed to write normalized module"));
    assert_eq!(
        fs::read_to_string(output_directory.join("A-MIB.mib")).expect("read earlier output"),
        "sentinel"
    );
    assert!(!output_directory.join("Z-REJECTED-MIB.mib").exists());
    let names = fs::read_dir(&output_directory)
        .expect("read output directory")
        .map(|entry| {
            entry
                .expect("read directory entry")
                .file_name()
                .into_string()
                .expect("UTF-8 filename")
        })
        .collect::<Vec<_>>();
    assert_eq!(names, ["A-MIB.mib"]);
}

#[test]
fn later_filesystem_failure_keeps_earlier_atomic_file_and_no_temporary_file() {
    let directory = TestDir::new();
    let output_directory = directory.path().join("partial-normalized");
    fs::create_dir(&output_directory).expect("create output directory");
    fs::create_dir(output_directory.join("B-MIB.mib")).expect("create blocking directory");

    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
            "B-MIB",
            "A-MIB",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to write normalized module B-MIB")
    );

    let a = fs::read_to_string(output_directory.join("A-MIB.mib")).expect("read completed A");
    assert!(a.starts_with("A-MIB DEFINITIONS ::= BEGIN\n"));
    assert!(output_directory.join("B-MIB.mib").is_dir());
    assert!(
        fs::read_dir(&output_directory)
            .expect("read output directory")
            .all(|entry| !entry
                .expect("read directory entry")
                .file_name()
                .to_string_lossy()
                .contains(".tmp-"))
    );
}

#[test]
fn invalid_module_name_fails_without_stdout_or_output_files() {
    let directory = TestDir::new();
    let output_directory = directory.path().join("invalid-normalized");
    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
            "MISSING-MIB",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output_directory.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("MISSING-MIB"));
}

#[test]
fn case_colliding_module_filenames_are_rejected_before_directory_creation() {
    let directory = TestDir::new();
    for (name, arc) in [("CASE-MIB", 424272), ("Case-MIB", 424273)] {
        let source = format!(
            "{name} DEFINITIONS ::= BEGIN\nroot OBJECT IDENTIFIER ::= {{ iso {arc} }}\nEND\n"
        );
        fs::write(directory.path().join(format!("{name}.mib")), source)
            .expect("write colliding module");
    }
    let output_directory = directory.path().join("collision-normalized");
    let output = run_normalize(
        &directory,
        &[
            "--output-dir",
            output_directory.to_str().expect("UTF-8 output path"),
            "CASE-MIB",
            "Case-MIB",
        ],
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!output_directory.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("colliding output filenames"));
}
