#![cfg(feature = "cli")]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

const TEST_MIB: &str = r#"TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, enterprises, Integer32
        FROM SNMPv2-SMI
    OBJECT-GROUP, MODULE-COMPLIANCE, AGENT-CAPABILITIES
        FROM SNMPv2-CONF;

testMib MODULE-IDENTITY
    LAST-UPDATED "202603150000Z"
    ORGANIZATION "Test"
    CONTACT-INFO "Test"
    DESCRIPTION "Test module."
    ::= { enterprises 99999 }

testScalar OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A test scalar."
    ::= { testMib 1 }

testNotification NOTIFICATION-TYPE
    OBJECTS { testScalar }
    STATUS current
    DESCRIPTION "A test notification."
    ::= { testMib 0 1 }

testBare OBJECT IDENTIFIER ::= { testMib 2 }

testGroup OBJECT-GROUP
    OBJECTS { testScalar }
    STATUS current
    DESCRIPTION "A test group."
    ::= { testMib 3 }

testCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "A test compliance statement."
    MODULE
        MANDATORY-GROUPS { testGroup }
    ::= { testMib 4 }

testCapabilities AGENT-CAPABILITIES
    PRODUCT-RELEASE "test"
    STATUS current
    DESCRIPTION "Test capabilities."
    SUPPORTS TEST-MIB
        INCLUDES { testGroup }
    ::= { testMib 5 }
END
"#;

struct TestDir(PathBuf);

impl TestDir {
    fn with_mib() -> Self {
        let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mib-rs-cli-find-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).expect("create test directory");
        fs::write(path.join("TEST-MIB.mib"), TEST_MIB).expect("write test MIB");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_find(directory: &TestDir, format: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mib-rs"))
        .args([
            "--path",
            directory.0.to_str().expect("UTF-8 test path"),
            "find",
            "--module",
            "TEST-MIB",
            "--type",
            "Integer32",
            "--format",
            format,
            "test*",
        ])
        .output()
        .expect("run mib-rs find")
}

#[test]
fn find_type_excludes_entities_without_types_from_text_output() {
    let directory = TestDir::with_mib();
    let output = run_find(&directory, "text");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 stdout"),
        "TEST-MIB::testScalar 1.3.6.1.4.1.99999.1 scalar\n"
    );
}

#[test]
fn find_type_excludes_entities_without_types_from_json_output() {
    let directory = TestDir::with_mib();
    let output = run_find(&directory, "json");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let matches: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON stdout");
    assert_eq!(
        matches,
        serde_json::json!([{
            "name": "testScalar",
            "module": "TEST-MIB",
            "oid": "1.3.6.1.4.1.99999.1",
            "kind": "scalar"
        }])
    );
}
