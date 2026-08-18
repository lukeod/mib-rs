//! Combine lossless syntax context with resolved symbol navigation.

use std::sync::Arc;

use mib_rs::compile::{SymbolNavigator, parse};
use mib_rs::{ByteOffset, Loader, SourceCandidate, SourceOrigin};

const MODULE: &str = "DOC-EXAMPLE-MIB";
const SOURCE: &[u8] = include_bytes!("../tests/data/doc-example-mib.txt");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let candidate = SourceCandidate::new(
        MODULE,
        SourceOrigin::memory(MODULE),
        format!("<memory:{MODULE}>"),
        Arc::<[u8]>::from(SOURCE),
    );
    let (tree, diagnostics) = parse(candidate)?;
    assert!(diagnostics.is_empty());

    let definition = b"docDescr OBJECT-TYPE";
    let offset = SOURCE
        .windows(definition.len())
        .position(|window| window == definition)
        .map(ByteOffset::try_from)
        .transpose()?
        .expect("the example definition should exist");

    // cursor_context works without semantic resolution and retains trivia and
    // recovery context from the lossless syntax tree.
    let syntax = tree
        .cursor_context(offset)
        .expect("the definition offset should be valid");
    println!("Syntax token: {:?}", syntax.token().kind());
    println!("In definition: {}", syntax.definition().is_some());

    let mib = Loader::new()
        .source(mib_rs::source::memory(MODULE, SOURCE))
        .modules([MODULE])
        .load()?;
    let module = mib.module(MODULE).expect("the module should be loaded");

    // SymbolNavigator verifies that the CST and semantic module refer to the
    // same origin and bytes before it combines their independently owned ranges.
    let navigator = SymbolNavigator::new(&tree, Some(module))?;
    let result = navigator
        .symbol_at(offset)
        .expect("the definition offset should be valid");
    let semantic = result
        .semantic
        .expect("the definition should resolve semantically");
    let primary = result.primary_range();

    println!("Semantic kind: {:?}", semantic.kind);
    println!("Declared name: {}", semantic.declared_name);
    println!("Primary text: {}", String::from_utf8_lossy(primary.text()?));

    Ok(())
}
