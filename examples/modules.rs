//! Module metadata, imports, revisions, base modules, and module-scoped
//! iteration.

use mib_rs::Loader;

fn main() {
    let source = mib_rs::source::memory(
        "EXAMPLE-FULL-MIB",
        include_bytes!("../tests/data/example-full-mib.txt").as_slice(),
    );

    let mib = Loader::new()
        .source(source)
        .modules(["EXAMPLE-FULL-MIB"])
        .load()
        .expect("should load");

    // -- List all loaded modules --
    println!("=== All loaded modules ===");
    for module in mib.modules() {
        let tag = if module.is_base() { " (base)" } else { "" };
        println!("  {:<30} {:?}{}", module.name(), module.language(), tag,);
    }

    // -- Module handle basics --
    let module = mib.module("EXAMPLE-FULL-MIB").unwrap();
    println!("\n=== {} (handle) ===", module.name());
    println!("  Language:    {:?}", module.language());
    println!("  Is base:     {}", module.is_base());
    println!("  Source path: {}", module.source_path());
    if let Some(oid) = module.oid() {
        println!("  OID:         {oid}");
    }

    // -- Module metadata from MODULE-IDENTITY --
    println!("\n=== {} (metadata) ===", module.name());
    println!("  Organization: {}", module.organization());
    println!("  Contact:      {}", module.contact_info());
    println!("  Description:  {}", module.description());
    println!("  Last updated: {}", module.last_updated());

    // -- Revisions --
    println!("\n  Revisions:");
    for rev in module.revisions() {
        println!("    {} - {}", rev.date, rev.description);
    }

    // -- Imports --
    println!("\n  Imports:");
    for imp in module.imports() {
        let symbols: Vec<_> = imp.symbols.iter().map(|s| s.name.as_str()).collect();
        println!("    FROM {}: {}", imp.module, symbols.join(", "));
    }

    // -- Module-scoped lookups (via handle) --
    println!("\n  Module-scoped object lookup:");
    let obj = module.object("exDeviceName").expect("object in module");
    println!("    {} ({:?})", obj.name(), obj.access());

    println!("\n  Module-scoped type lookup:");
    let ty = module.r#type("ExPercentage").expect("type in module");
    println!("    {} (base={:?})", ty.name(), ty.effective_base());

    // Cross-check: object's module matches
    assert_eq!(obj.module().unwrap().name(), module.name());

    // -- Module-scoped iteration --
    println!("\n  Objects in module:");
    for obj in module.objects() {
        println!("    {:<24} {:?}", obj.name(), obj.kind());
    }

    println!("\n  Types in module:");
    for ty in module.types() {
        println!("    {:<24} {:?}", ty.name(), ty.effective_base());
    }

    println!("\n  Nodes in module:");
    let mut count = 0;
    for node in module.nodes() {
        count += 1;
        if count <= 5 {
            println!("    {:<24} {}", node.name(), node.oid());
        }
    }
    if count > 5 {
        println!("    ... and {} more", count - 5);
    }

    // -- Base module inspection --
    // Seven base modules are always present in every loaded Mib. They define
    // the SMI language itself (ASN.1 macros like OBJECT-TYPE, MODULE-IDENTITY,
    // TEXTUAL-CONVENTION) plus the core types and OID tree roots.
    //
    // Embedded RFC-derived text, byte-synchronized with gomib and deliberately
    // adapted where needed, supplies a lowest-priority parsed fallback:
    //   - You don't need to supply them as source files
    //   - Copies from configured sources take priority
    //   - Definitions have ordinary source spans
    //   - Embedded source paths use the "embedded:MODULE" form
    //
    // Use is_base() to distinguish them from user-supplied modules.
    let base = mib.module("SNMPv2-SMI").unwrap();
    println!("\n=== Base module: {} ===", base.name());
    println!("  Is base:      {}", base.is_base());
    println!("  Language:     {:?}", base.language());
    println!("  Source path:  {:?}", base.source_path());

    // Base modules provide the well-known OID tree roots.
    println!("  Some nodes:");
    for name in ["iso", "internet", "mgmt", "mib-2", "enterprises"] {
        if let Some(node) = base.node(name) {
            println!("    {:<16} {}", node.name(), node.oid());
        }
    }

    // -- Which modules define/import a symbol --
    let definers = mib.modules_defining("exDeviceName");
    println!("\nModules defining 'exDeviceName': {}", definers.len());

    let importers = mib.modules_importing("DisplayString");
    println!("Modules importing 'DisplayString': {}", importers.len());

    // -- All symbols across the MIB --
    // Symbol is a raw-level enum (stores arena IDs), so module() returns
    // ModuleId. Use module_by_id() to get back to a handle for the name.
    let symbols = mib.all_symbols();
    let module_symbols: Vec<_> = symbols
        .iter()
        .filter(|s| {
            s.module(&mib)
                .map(|mid| mib.module_by_id(mid).name() == "EXAMPLE-FULL-MIB")
                .unwrap_or(false)
        })
        .collect();
    println!(
        "\nTotal symbols in EXAMPLE-FULL-MIB: {}",
        module_symbols.len()
    );
}
