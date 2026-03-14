//! OID tree walking: root traversal, subtree iteration, depth-first walk,
//! and node navigation.

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

    // -- Root node --
    let root = mib.root_node();
    println!("Root: name={:?}, oid={}", root.name(), root.oid());

    // -- Top-level children of the OID tree --
    println!("\n=== Top-level arcs ===");
    for child in root.children() {
        println!("  {} (arc={})", child.name(), child.arc());
    }

    // -- Walking from a specific subtree --
    let start = mib.resolve_node("exObjects").expect("should resolve");
    println!("\n=== Subtree of {} ({}) ===", start.name(), start.oid());
    for node in start.subtree() {
        // Compute depth relative to start for indentation.
        let depth = node.oid().len() - start.oid().len();
        let indent = "  ".repeat(depth);
        let kind = node.kind();
        println!("  {indent}{} ({}) [{kind:?}]", node.name(), node.oid());
    }

    // -- Node parent navigation --
    let leaf = mib.resolve_node("exIfOutOctets").unwrap();
    println!("\n=== Parent chain from {} ===", leaf.name());
    let mut current = Some(leaf);
    while let Some(node) = current {
        println!("  {} ({})", node.name(), node.oid());
        current = node.parent();
    }

    // -- Children of a specific node --
    let entry = mib.resolve_node("exIfEntry").unwrap();
    println!("\n=== Children of {} ===", entry.name());
    for child in entry.children() {
        let obj_info = child
            .object()
            .map(|o| format!("{:?} {:?}", o.access(), o.kind()))
            .unwrap_or_else(|| "no object".into());
        println!("  arc={}: {} - {}", child.arc(), child.name(), obj_info);
    }

    // -- Node properties --
    let node = mib.resolve_node("exDeviceName").unwrap();
    println!("\n=== Node properties: {} ===", node.name());
    println!("  OID:         {}", node.oid());
    println!("  Arc:         {}", node.arc());
    println!("  Kind:        {:?}", node.kind());
    println!("  Status:      {:?}", node.status());
    println!("  Description: {}", node.description());
    println!(
        "  Module:      {:?}",
        node.module().map(|m| m.name().to_string())
    );

    // Object attached to this node
    if let Some(obj) = node.object() {
        println!("  Object:      {} ({:?})", obj.name(), obj.access());
    }

    // -- Notification attached to a node --
    let node = mib.resolve_node("exStatusChange").unwrap();
    if let Some(notif) = node.notification() {
        println!("\n=== Notification on node {} ===", node.name());
        println!("  Name: {}", notif.name());
    }

    // -- Total node count --
    println!("\nTotal OID tree nodes: {}", mib.node_count());

    // -- Iterate all nodes via Mib::nodes() --
    println!("\n=== All named nodes ===");
    let mut count = 0;
    for node in mib.nodes() {
        count += 1;
        if count <= 10 {
            println!("  {:<30} {}", node.name(), node.oid());
        }
    }
    if count > 10 {
        println!("  ... and {} more", count - 10);
    }
}
