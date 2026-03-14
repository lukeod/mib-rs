//! Low-level raw data access using arena IDs and the RawMib view.
//!
//! The raw API is useful for tooling that needs stable IDs, direct
//! arena access, or the OID tree structure.

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

    // -- Get a raw view --
    let raw = mib.raw();

    // -- Arena sizes via slices --
    println!("=== Arena sizes ===");
    println!("  Modules:       {}", mib.modules_slice().len());
    println!("  Objects:       {}", mib.objects_slice().len());
    println!("  Types:         {}", mib.types_slice().len());
    println!("  Notifications: {}", mib.notifications_slice().len());
    println!("  Groups:        {}", mib.groups_slice().len());
    println!("  Compliances:   {}", mib.compliances_slice().len());
    println!("  Node count:    {}", mib.node_count());

    // -- Access object data through arena slices --
    // ObjectData, TypeData, etc. expose the same accessor methods
    // that the high-level handles delegate to.
    println!("\n=== Objects (via slice) ===");
    for obj_data in mib.objects_slice() {
        println!(
            "  {:<24} node={:<10?} type={:<10?}",
            obj_data.name(),
            obj_data.node(),
            obj_data.type_id(),
        );
    }

    // -- Type data --
    println!("\n=== Types (via slice) ===");
    for type_data in mib.types_slice() {
        println!(
            "  {:<24} base={:?}  parent={:?}",
            type_data.name(),
            type_data.base(),
            type_data.parent(),
        );
    }

    // -- Access data by arena ID (obtained from lookups) --
    // IDs come from name lookups, symbol enumeration, or cross-references
    // in data records. You can then use raw.object(id), raw.node(id), etc.
    println!("\n=== Raw lookup by ID ===");
    let obj_id = mib.object_by_name("docDeviceName").unwrap();
    let obj_data = raw.object(obj_id);
    println!("  Object: {}", obj_data.name());
    println!("  Status: {:?}", obj_data.status());
    println!("  Access: {:?}", obj_data.access());

    // Follow the type reference.
    if let Some(type_id) = obj_data.type_id() {
        let type_data = raw.type_(type_id);
        println!(
            "  Type:   {} (base={:?})",
            type_data.name(),
            type_data.base()
        );
    }

    // Follow the node reference.
    if let Some(node_id) = obj_data.node() {
        let node_data = raw.node(node_id);
        println!("  Node:   {} (arc={})", node_data.name(), node_data.arc());
    }

    // -- OID tree direct access --
    println!("\n=== OID tree ===");
    let root_id = raw.root();
    let root_data = raw.node(root_id);
    println!("  Root children: {}", root_data.children().len());

    // Walk to a specific OID
    let target_oid: mib_rs::Oid = "1.3.6.1.4.1.99999".parse().unwrap();
    if let Some(node_id) = raw.node_by_oid(&target_oid) {
        let data = raw.node(node_id);
        println!("  Exact OID {target_oid}: name={}", data.name());
    }

    // Longest prefix match
    let instance_oid: mib_rs::Oid = "1.3.6.1.4.1.99999.2.1.1.2.42".parse().unwrap();
    let prefix_id = raw.longest_prefix_by_oid(&instance_oid);
    let prefix_data = raw.node(prefix_id);
    println!(
        "  Longest prefix for {instance_oid}: name={}",
        prefix_data.name()
    );

    // -- Symbol enumeration --
    println!("\n=== Symbols in DOC-EXAMPLE-MIB ===");
    let symbols = mib.all_symbols();
    for sym in &symbols {
        let name = sym.name(&mib);
        let mod_id = sym.module(&mib);
        let mod_name = mod_id
            .map(|id| raw.module(id).name().to_string())
            .unwrap_or_default();
        let kind = match sym {
            mib_rs::raw::Symbol::Object(_) => "object",
            mib_rs::raw::Symbol::Type(_) => "type",
            mib_rs::raw::Symbol::Node(_) => "node",
            mib_rs::raw::Symbol::Notification(_) => "notification",
            mib_rs::raw::Symbol::Group(_) => "group",
            mib_rs::raw::Symbol::Compliance(_) => "compliance",
            mib_rs::raw::Symbol::Capability(_) => "capability",
        };
        if mod_name == "DOC-EXAMPLE-MIB" {
            println!("  {:<24} {:<14} {}", name, kind, mod_name);
        }
    }

    // -- ID round-trip: name -> ID -> raw data, vs name -> handle --
    let obj_id = mib.object_by_name("docDeviceName").unwrap();
    let obj_raw = raw.object(obj_id);
    let obj_handle = mib.object("docDeviceName").unwrap();
    assert_eq!(obj_raw.name(), obj_handle.name());
    println!(
        "\n  ID round-trip: {} (raw) == {} (handle)",
        obj_raw.name(),
        obj_handle.name()
    );

    // Arena IDs expose their raw index for serialization or external storage.
    println!("  ObjectId index: {}", obj_id.index());

    // -- Node children via raw data --
    let entry_node_id = mib.resolve("docEntry").unwrap();
    let entry_data = raw.node(entry_node_id);
    println!("\n=== Children of {} (via raw) ===", entry_data.name());
    for (arc, &child_id) in entry_data.children() {
        let child = raw.node(child_id);
        println!("  arc={}: {}", arc, child.name());
    }
}
