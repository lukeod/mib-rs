//! JSON export of a resolved MIB using the serde-based export API.

use mib_rs::{Loader, ResolverStrictness};

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

    // -- Export to JSON --
    let payload = mib_rs::export::export_v1(&mib, ResolverStrictness::Normal);

    // The payload is a fully serializable structure.
    let json = serde_json::to_string_pretty(&payload).expect("should serialize");
    println!("=== JSON export (truncated) ===");

    // Print just the first 80 lines to keep output manageable.
    for (i, line) in json.lines().enumerate() {
        if i >= 80 {
            println!("... ({} more lines)", json.lines().count() - 80);
            break;
        }
        println!("{line}");
    }

    // -- Inspect export payload fields --
    println!("\n=== Export payload structure ===");
    println!("  Schema version: {}", payload.schema_version);
    println!("  Export kind:    {}", payload.export_kind);
    println!("  Strictness:     {}", payload.strictness);
    println!(
        "  Exporter:       {} v{}",
        payload.exporter.implementation, payload.exporter.version
    );
    println!("  Modules:        {}", payload.modules.len());
    println!("  Types:          {}", payload.types.len());
    println!("  Nodes:          {}", payload.nodes.len());
    println!("  Objects:        {}", payload.objects.len());
    println!("  Notifications:  {}", payload.notifications.len());
    println!("  Groups:         {}", payload.groups.len());
    println!("  Compliances:    {}", payload.compliances.len());
    println!("  Diagnostics:    {}", payload.diagnostics.len());

    // -- Inspect exported objects --
    println!("\n=== Exported objects ===");
    for obj in &payload.objects {
        println!(
            "  {:<24} oid={:<30} kind={} access={}",
            obj.name, obj.oid, obj.kind, obj.access,
        );
    }

    // -- Inspect exported types --
    println!("\n=== Exported types ===");
    for ty in &payload.types {
        println!(
            "  {:<24} module={:<20} base={}",
            ty.name, ty.module, ty.base,
        );
    }

    // -- Inspect exported nodes (first few) --
    println!("\n=== Exported nodes (first 10) ===");
    for node in payload.nodes.iter().take(10) {
        println!("  {:<30} {}", node.name, node.oid);
    }
    if payload.nodes.len() > 10 {
        println!("  ... and {} more", payload.nodes.len() - 10);
    }
}
