use std::sync::Arc;

use mib_rs::compile::{
    CstNode, Definition, Module, SourceFile, SyntaxElement, SyntaxKind, SyntaxNode, SyntaxToken,
    SyntaxTree, parse, parse_with_config,
};
use mib_rs::{DiagnosticConfig, SourceCandidate, SourceOrigin};

const SOURCE: &[u8] =
    b"PUBLIC-MIB DEFINITIONS ::= BEGIN\nvalue OBJECT IDENTIFIER ::= { 1 3 6 }\nEND\n";

fn candidate(bytes: impl Into<Arc<[u8]>>) -> SourceCandidate {
    SourceCandidate::new(
        "public-cst-api",
        SourceOrigin::memory("public-cst-api"),
        "PUBLIC-MIB",
        bytes,
    )
}

fn parse_local_allocation() -> SyntaxTree {
    let bytes = SOURCE.to_vec();
    parse(candidate(Arc::<[u8]>::from(bytes)))
        .expect("test source should fit source ranges")
        .0
}

fn module_name<'tree, 'src>(module: Module<'tree, 'src>) -> &'src [u8] {
    module.header().unwrap().name().unwrap().text()
}

fn token_text<'tree, 'src>(token: SyntaxToken<'tree, 'src>) -> &'src [u8] {
    token.text()
}

fn node_kind(node: SyntaxNode<'_, '_>) -> SyntaxKind {
    node.kind()
}

#[test]
fn documented_compile_reexports_form_a_usable_public_api() {
    let tree = parse_local_allocation();
    assert_eq!(tree.document().bytes(), SOURCE);
    assert_eq!(tree.document().label(), "PUBLIC-MIB");
    assert_eq!(
        tree.document().origin(),
        &SourceOrigin::memory("public-cst-api")
    );
    assert_eq!(tree.reconstruct_text(), SOURCE);

    let root: SourceFile<'_, '_> = tree.source_file();
    let module = root.modules().next().unwrap();
    assert_eq!(module_name(module), b"PUBLIC-MIB");
    let _: SyntaxNode<'_, '_> = CstNode::syntax(module);

    let definition: Definition<'_, '_> = module.definitions().next().unwrap();
    assert!(matches!(definition, Definition::ValueAssignment(_)));
    assert_eq!(node_kind(definition.syntax()), SyntaxKind::ValueAssignment);

    let first = tree.root().children().next().unwrap();
    let _: SyntaxElement<'_, '_> = first;
    assert!(first.as_node().is_some());

    let name = tree
        .tokens()
        .find(|token| token.kind() == SyntaxKind::UppercaseIdent)
        .unwrap();
    assert_eq!(token_text(name), b"PUBLIC-MIB");
}

#[test]
fn configured_entry_point_returns_diagnostics_with_the_owned_tree() {
    let input = Arc::<[u8]>::from(b"BROKEN-MIB DEFINITIONS ::= BEGIN\n@\nEND".as_slice());
    let (tree, diagnostics) =
        parse_with_config(candidate(input), &DiagnosticConfig::verbose()).unwrap();

    assert!(!diagnostics.is_empty());
    for entry in diagnostics.iter() {
        let Some((document, range)) = entry.range().unwrap() else {
            continue;
        };
        assert!(std::ptr::eq(document, tree.document()));
        assert_eq!(range.source(), tree.document().id());
        assert!(entry.slice().unwrap().is_some());
        assert!(entry.byte_positions().unwrap().is_some());
    }
    assert_eq!(
        tree.reconstruct_text(),
        b"BROKEN-MIB DEFINITIONS ::= BEGIN\n@\nEND"
    );
}

#[test]
fn simultaneous_parse_reports_do_not_cross_resolve_aliased_source_ids() {
    let first_bytes = b"FIRST-MIB DEFINITIONS ::= BEGIN\n@\nEND";
    let second_bytes = b"SECOND-MIB DEFINITIONS ::= BEGIN\n$\nEND";
    let first = SourceCandidate::new(
        "first",
        SourceOrigin::memory("first"),
        "FIRST-MIB",
        Arc::<[u8]>::from(first_bytes.as_slice()),
    );
    let second = SourceCandidate::new(
        "second",
        SourceOrigin::memory("second"),
        "SECOND-MIB",
        Arc::<[u8]>::from(second_bytes.as_slice()),
    );

    let (first_tree, first_report) = parse(first).unwrap();
    let (second_tree, second_report) = parse(second).unwrap();

    // Source IDs are compilation-local and deliberately alias here.
    assert_eq!(first_tree.document().id(), second_tree.document().id());

    let first_entry = first_report
        .iter()
        .find(|entry| entry.slice().unwrap() == Some(b"@".as_slice()))
        .unwrap();
    let second_entry = second_report
        .iter()
        .find(|entry| entry.slice().unwrap() == Some(b"$".as_slice()))
        .unwrap();
    let first_document = first_entry.range().unwrap().unwrap().0;
    let second_document = second_entry.range().unwrap().unwrap().0;

    assert!(std::ptr::eq(first_document, first_tree.document()));
    assert!(std::ptr::eq(second_document, second_tree.document()));
    assert!(!std::ptr::eq(first_document, second_tree.document()));
    assert!(!std::ptr::eq(second_document, first_tree.document()));
    assert_eq!(first_entry.slice().unwrap(), Some(b"@".as_slice()));
    assert_eq!(second_entry.slice().unwrap(), Some(b"$".as_slice()));
    assert!(first_entry.render().unwrap().contains("FIRST-MIB"));
    assert!(second_entry.render().unwrap().contains("SECOND-MIB"));
}
