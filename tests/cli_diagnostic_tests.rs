#![cfg(feature = "cli")]

use std::process::Command;

#[test]
fn lint_list_codes_exports_empty_revision_description() {
    let output = Command::new(env!("CARGO_BIN_EXE_mib-rs"))
        .args(["lint", "--list-codes"])
        .output()
        .expect("run mib-rs lint --list-codes");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    assert!(
        stdout
            .lines()
            .any(|line| line.split_whitespace().next() == Some("empty-revision-description")),
        "diagnostic code listing did not export empty-revision-description:\n{stdout}"
    );
}
