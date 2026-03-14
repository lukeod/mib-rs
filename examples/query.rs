//! Demonstrate all query formats: plain names, qualified names, numeric OIDs,
//! instance OIDs, and OID formatting.

use mib_rs::Loader;

fn main() {
    let source = mib_rs::source::memory(
        "DOC-EXAMPLE-MIB",
        include_bytes!("../tests/data/doc-example-mib.txt").as_slice(),
    );

    let mib = Loader::new()
        .source(source)
        .modules(["DOC-EXAMPLE-MIB"])
        .load()
        .expect("should load");

    // -- Plain name lookup --
    // resolve_node returns the Node handle for a name.
    let node = mib.resolve_node("docDeviceName").expect("should resolve");
    println!("Plain name lookup:");
    println!("  Name: {}", node.name());
    println!("  OID:  {}", node.oid());
    println!("  Kind: {:?}", node.kind());

    // -- Qualified name (MODULE::name) --
    // Scopes the lookup to a specific module.
    let node = mib
        .resolve_node("DOC-EXAMPLE-MIB::docDeviceName")
        .expect("should resolve");
    println!("\nQualified name lookup:");
    println!("  Name: {}", node.name());
    println!("  OID:  {}", node.oid());

    // -- Numeric OID --
    let oid_str = "1.3.6.1.4.1.99999.1.1";
    let node = mib.resolve_node(oid_str).expect("should resolve");
    println!("\nNumeric OID lookup ({oid_str}):");
    println!("  Name: {}", node.name());
    println!("  OID:  {}", node.oid());

    // -- Leading-dot numeric OID --
    let node = mib
        .resolve_node(".1.3.6.1.4.1.99999.1.1")
        .expect("should resolve");
    println!("\nLeading-dot OID: {}", node.name());

    // -- resolve_oid: symbolic name to numeric OID --
    let oid = mib.resolve_oid("docDescr").expect("should resolve");
    println!("\nresolve_oid(\"docDescr\"): {oid}");

    // -- Instance OIDs (name.suffix) --
    // resolve_node returns the deepest matching tree node.
    let node = mib
        .resolve_node("docDescr.7")
        .expect("should resolve instance");
    println!("\nInstance OID - resolve_node(\"docDescr.7\"):");
    println!(
        "  Node name: {} (the base node, not the instance)",
        node.name()
    );

    // resolve_oid returns the full numeric OID with suffix included.
    let instance_oid = mib
        .resolve_oid("docDescr.7")
        .expect("should resolve instance");
    println!("  Full OID:  {instance_oid}");

    // Multi-component instance suffix
    let deep = mib.resolve_oid("docDescr.1.2.3").expect("should resolve");
    println!("  Multi-suffix: {deep}");

    // -- Numeric instance OID --
    let parsed: mib_rs::Oid = "1.3.6.1.4.1.99999.2.1.1.2.42".parse().unwrap();
    let node = mib.lookup_oid(&parsed);
    println!(
        "\nlookup_oid(\"...2.42\"): {} (longest prefix match)",
        node.name()
    );

    // exact_node_by_oid only matches if the OID is an exact tree node.
    let exact = mib.exact_node_by_oid(&parsed);
    println!(
        "exact_node_by_oid: {:?} (None because .42 is an instance)",
        exact.map(|n| n.name())
    );

    let base_oid: mib_rs::Oid = "1.3.6.1.4.1.99999.2.1.1.2".parse().unwrap();
    let exact = mib.exact_node_by_oid(&base_oid);
    println!(
        "exact_node_by_oid(base): {:?} (exact match)",
        exact.map(|n| n.name())
    );

    // -- format_oid: numeric OID back to MODULE::name.suffix --
    let oid = mib.resolve_oid("docDescr.7").unwrap();
    let formatted = mib.format_oid(&oid);
    println!("\nformat_oid: {formatted}");

    // Round-trip: formatted string back to OID.
    let round_trip = mib.resolve_oid(&formatted).unwrap();
    println!("Round-trip:  {round_trip}");
    assert_eq!(oid, round_trip);

    // -- resolve: returns NodeId (lower-level) --
    let node_id = mib.resolve("docTable");
    println!("\nresolve(\"docTable\"): {:?}", node_id);

    // -- symbol_by_name: untyped symbol lookup --
    let sym = mib.symbol_by_name("DocName").expect("type should exist");
    println!("symbol_by_name(\"DocName\"): {:?}", sym);

    // -- Module-scoped lookups --
    let module = mib.module("DOC-EXAMPLE-MIB").unwrap();
    let obj = module.object("docDeviceName").expect("in module");
    println!("\nModule-scoped: {}.{}", module.name(), obj.name());

    let ty = module.r#type("DocName").expect("type in module");
    println!(
        "Module-scoped type: {} (tc={})",
        ty.name(),
        ty.is_textual_convention()
    );

    // -- OID tree: children and subtree --
    let table_node = mib.resolve_node("docTable").unwrap();
    println!("\nChildren of {}:", table_node.name());
    for child in table_node.children() {
        println!("  {} ({})", child.name(), child.oid());
    }

    println!("\nSubtree of {}:", table_node.name());
    for node in table_node.subtree() {
        println!("  {} ({})", node.name(), node.oid());
    }
}
