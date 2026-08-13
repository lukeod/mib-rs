use mib_rs::{Loader, source};

#[test]
fn doc_example_mib_loads_without_default_diagnostics() {
    let mib = Loader::new()
        .source(source::memory(
            "DOC-EXAMPLE-MIB",
            include_bytes!("data/doc-example-mib.txt").as_slice(),
        ))
        .modules(["DOC-EXAMPLE-MIB"])
        .load()
        .expect("DOC-EXAMPLE-MIB should load");

    assert!(mib.diagnostics().is_empty(), "{:?}", mib.diagnostics());
}

#[test]
fn full_example_mib_loads_without_default_diagnostics() {
    let mib = Loader::new()
        .source(source::memory(
            "EXAMPLE-FULL-MIB",
            include_bytes!("data/example-full-mib.txt").as_slice(),
        ))
        .modules(["EXAMPLE-FULL-MIB"])
        .load()
        .expect("EXAMPLE-FULL-MIB should load");

    assert!(mib.diagnostics().is_empty(), "{:?}", mib.diagnostics());
}
