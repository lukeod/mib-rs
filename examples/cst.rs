//! Parse and inspect a lossless concrete syntax tree.

use std::sync::Arc;

use mib_rs::compile::{Definition, SyntaxKind, parse};
use mib_rs::{SourceCandidate, SourceOrigin};

fn main() {
    let source = br#"EXAMPLE-MIB DEFINITIONS ::= BEGIN

@ invalid input retained for recovery
example OBJECT IDENTIFIER ::= { 1 3 6 1 }
END
"#;
    let candidate = SourceCandidate::new(
        "cst-example",
        SourceOrigin::memory("cst-example"),
        "EXAMPLE-MIB",
        Arc::<[u8]>::from(source.as_slice()),
    );

    let (tree, diagnostics) = parse(candidate).expect("example source should fit source ranges");

    // Traverse typed modules and definitions.
    for module in tree.source_file().modules() {
        let name = module
            .header()
            .and_then(|header| header.name())
            .map(|token| String::from_utf8_lossy(token.text()))
            .unwrap_or_default();
        println!("module {name}");

        for definition in module.definitions() {
            if let Definition::ValueAssignment(value) = definition {
                println!(
                    "  value {}",
                    String::from_utf8_lossy(value.name().unwrap().text())
                );
            }
        }
    }

    // Untyped token traversal exposes exact token text, including trivia.
    for token in tree
        .tokens()
        .filter(|token| !matches!(token.kind(), SyntaxKind::Whitespace | SyntaxKind::EofToken))
    {
        println!(
            "{:?}: {:?}",
            token.kind(),
            String::from_utf8_lossy(token.text())
        );
    }

    // Report-owned entries bind diagnostics to the same source arena as the tree.
    for entry in diagnostics.iter() {
        let text = entry
            .slice()
            .expect("the report retains every diagnostic source");
        let positions = entry
            .byte_positions()
            .expect("the report retains every diagnostic source");
        println!(
            "{}: {:?} at {positions:?}",
            entry.diagnostic(),
            text.map(String::from_utf8_lossy)
        );
    }

    // The CST is lossless even when the input contains errors.
    assert_eq!(tree.reconstruct_text(), source);
}
