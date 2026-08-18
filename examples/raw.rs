//! Low-level raw data access for tooling: arena IDs, sub-clause ranges,
//! import metadata, OID references, symbol tables, and OID tree traversal.
//!
//! The raw API (`mib.raw()`) is designed for tools that need capabilities
//! beyond the handle API: linters, language servers, exporters, and editor
//! integrations. This example demonstrates what it offers that the handle
//! API does not.

use mib_rs::Loader;

fn main() {
    // The fixture contains both used and unused imports so the example can
    // show the import-resolution metadata.
    let source = mib_rs::source::memory(
        "RAW-EXAMPLE-MIB",
        br#"RAW-EXAMPLE-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    TEXTUAL-CONVENTION, DisplayString, TruthValue
        FROM SNMPv2-TC;

rawMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example Corp"
    CONTACT-INFO "support@example.com"
    DESCRIPTION "Example module for raw API demo."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 99990 }

RawName ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "255a"
    STATUS current
    DESCRIPTION "A name string."
    SYNTAX DisplayString (SIZE (1..64))

rawScalars OBJECT IDENTIFIER ::= { rawMib 1 }

rawDeviceName OBJECT-TYPE
    SYNTAX RawName
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "The device name."
    ::= { rawScalars 1 }

rawEnabled OBJECT-TYPE
    SYNTAX TruthValue
    MAX-ACCESS read-write
    STATUS current
    DESCRIPTION "Whether the device is enabled."
    DEFVAL { true }
    ::= { rawScalars 2 }

rawCount OBJECT-TYPE
    SYNTAX Integer32 (0..1000)
    UNITS "items"
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Item count."
    ::= { rawScalars 3 }

END
"#
        .as_slice(),
    );

    let mib = Loader::new()
        .source(source)
        .modules(["RAW-EXAMPLE-MIB"])
        .load()
        .expect("should load");

    let raw = mib.raw();

    // ---------------------------------------------------------------
    // 1. Sub-clause ranges
    //
    // ObjectData exposes per-clause source locations: syntax_range(),
    // access_range(), units_range(), augments_range(), default_value_range().
    // These let a linter or language server point diagnostics at the
    // specific clause that's wrong, not the whole definition.
    // ---------------------------------------------------------------
    println!("=== Sub-clause ranges ===");

    let mod_data = raw.module(mib.module_by_name("RAW-EXAMPLE-MIB").unwrap());
    let location = |range: mib_rs::SourceRange| {
        let source = raw.source(range.source())?;
        source.slice(range).ok()?;
        source.line_column(range.start()).ok()
    };

    for &obj_id in mod_data.objects() {
        let obj = raw.object(obj_id);
        println!("  {}:", obj.name());

        // Definition range covers the whole OBJECT-TYPE.
        let def = obj.range().expect("parsed object has a source range");
        let (def_line, _) = location(def).expect("valid object range");
        println!("    definition:    line {def_line}");

        // SYNTAX clause range.
        if let Some(syn) = obj.syntax_range() {
            let (line, col) = location(syn).expect("valid syntax range");
            println!("    SYNTAX:        line {line}, col {col}");
        }

        // MAX-ACCESS clause range.
        if let Some(acc) = obj.access_range() {
            let (line, col) = location(acc).expect("valid access range");
            println!("    MAX-ACCESS:    line {line}, col {col}");
        }

        // UNITS clause range (only present on some objects).
        if let Some(units) = obj.units_range() {
            let (line, col) = location(units).expect("valid units range");
            println!("    UNITS:         line {line}, col {col}");
        }

        // DEFVAL clause range (only present on some objects).
        if let Some(defval) = obj.default_value_range() {
            let (line, col) = location(defval).expect("valid default range");
            println!("    DEFVAL:        line {line}, col {col}");
        }
    }

    // TypeData also has syntax_range() for the SYNTAX clause in TCs.
    for &type_id in mod_data.types() {
        let ty = raw.type_(type_id);
        if let Some(syn) = ty.syntax_range() {
            let (line, col) = location(syn).expect("valid type syntax range");
            println!("  {} (type):", ty.name());
            println!("    SYNTAX:        line {line}, col {col}");
        }
    }

    // ---------------------------------------------------------------
    // 2. Import resolution metadata
    //
    // ModuleData tracks which imports were actually used during
    // resolution, and where each imported symbol was resolved from.
    // This is the data a linter needs for "unused import" warnings.
    // ---------------------------------------------------------------
    println!("\n=== Import analysis ===");

    for imp in mod_data.imports() {
        println!("  FROM {}:", imp.module);
        for sym in &imp.symbols {
            let used = mod_data.is_import_used(&sym.name);
            let resolved_from = mod_data.import_source(&sym.name);

            let status = if !used {
                "UNUSED".to_string()
            } else if let Some(source_id) = resolved_from {
                let source_mod = raw.module(source_id);
                if source_mod.name() != imp.module {
                    // Resolved from a different module than declared.
                    format!("resolved from {}", source_mod.name())
                } else {
                    "ok".to_string()
                }
            } else {
                "unresolved".to_string()
            };

            // ImportSymbol carries a range for "go to definition" on imports.
            let (line, col) = location(sym.range).expect("valid import range");
            println!("    {:<24} line {}:{:<4} {}", sym.name, line, col, status);
        }
    }

    // ---------------------------------------------------------------
    // 3. OID references (oid_refs)
    //
    // Entity definitions record the symbolic names referenced in their
    // OID value assignments. For example, { enterprises 99990 } produces
    // an OidRef for "enterprises" with its range. A language server uses
    // these for "go to definition" on OID components and for reference
    // highlighting.
    // ---------------------------------------------------------------
    println!("\n=== OID references ===");

    for &obj_id in mod_data.objects() {
        let obj = raw.object(obj_id);
        let refs = obj.oid_refs();
        if !refs.is_empty() {
            println!("  {}:", obj.name());
            for r in refs {
                let (line, col) = location(r.range).expect("valid OID reference range");
                println!("    ref {:?} at line {}:{}", r.name, line, col);
            }
        }
    }

    // ---------------------------------------------------------------
    // 4. Symbol tables and available_symbols
    //
    // Mib::available_symbols(mod_id) returns everything visible in a
    // module's scope: own definitions first, then resolved imports.
    // This is what a completion engine would use to suggest names.
    // ---------------------------------------------------------------
    println!("\n=== Available symbols in RAW-EXAMPLE-MIB ===");

    let mod_id = mib.module_by_name("RAW-EXAMPLE-MIB").unwrap();
    let symbols = mib.available_symbols(mod_id);

    // Show own definitions vs imported symbols.
    let own_count = mod_data.definitions().count();
    println!(
        "  {} own definitions, {} total (including imports)",
        own_count,
        symbols.len()
    );

    println!("\n  Own definitions:");
    for sym in symbols.iter().take(own_count) {
        let kind = match sym {
            mib_rs::raw::Symbol::Object(_) => "object",
            mib_rs::raw::Symbol::Type(_) => "type",
            mib_rs::raw::Symbol::Node(_) => "node",
            mib_rs::raw::Symbol::Notification(_) => "notification",
            mib_rs::raw::Symbol::Group(_) => "group",
            mib_rs::raw::Symbol::Compliance(_) => "compliance",
            mib_rs::raw::Symbol::Capability(_) => "capability",
        };
        println!("    {:<24} {}", sym.name(&mib), kind);
    }

    println!("\n  Imported symbols (first 10):");
    for sym in symbols.iter().skip(own_count).take(10) {
        let source_mod = sym
            .module(&mib)
            .map(|id| raw.module(id).name().to_string())
            .unwrap_or_default();
        println!("    {:<24} from {}", sym.name(&mib), source_mod);
    }

    // ---------------------------------------------------------------
    // 5. ID-only workflows
    //
    // Handles and raw access share the same arena IDs (ObjectId,
    // NodeId, etc.). Handles expose theirs via .id(), so you can
    // always get an ID. The raw layer lets you work entirely in IDs:
    // follow cross-refs like obj_data.type_id(), look up data with
    // raw.object(id), and iterate arenas without constructing
    // handles. IDs are Copy + Eq + Hash + Ord, so they work as map
    // keys or can be sent across channels.
    // ---------------------------------------------------------------
    println!("\n=== ID-only workflows ===");

    // Get an ID from a handle, or directly from Mib.
    let handle = mib.object("rawDeviceName").unwrap();
    let obj_id = handle.id(); // same as mib.object_by_name("rawDeviceName")
    println!("  ObjectId index: {}", obj_id.index());

    // Follow cross-references without handles.
    let obj_data = raw.object(obj_id);
    if let Some(type_id) = obj_data.type_id() {
        let type_data = raw.type_(type_id);
        println!(
            "  {} -> type {} (no handles needed)",
            obj_data.name(),
            type_data.name()
        );
    }

    // IDs can be collected into sets for deduplication.
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    seen.insert(obj_id);
    println!("  IDs are hashable: {}", seen.contains(&obj_id));

    // ---------------------------------------------------------------
    // 6. Bulk arena access
    //
    // raw.*_slice() gives direct &[Data] access to the arena backing
    // stores. No iterator adapters, no handle wrapping. Useful for
    // exporters, batch analysis, or building secondary indices.
    // ---------------------------------------------------------------
    println!("\n=== Arena slices ===");
    println!("  Modules:       {}", raw.modules_slice().len());
    println!("  Objects:       {}", raw.objects_slice().len());
    println!("  Types:         {}", raw.types_slice().len());
    println!("  Notifications: {}", raw.notifications_slice().len());

    // Build a quick index: type name -> list of objects using it.
    use std::collections::HashMap;
    let mut type_usage: HashMap<&str, Vec<&str>> = HashMap::new();
    for obj_data in raw.objects_slice() {
        if let Some(type_id) = obj_data.type_id() {
            let type_name = raw.type_(type_id).name();
            type_usage
                .entry(type_name)
                .or_default()
                .push(obj_data.name());
        }
    }

    println!("\n  Type usage index:");
    let mut entries: Vec<_> = type_usage.iter().collect();
    entries.sort_by_key(|(name, _)| *name);
    for (type_name, objects) in &entries {
        if objects.iter().any(|o| o.starts_with("raw")) {
            println!("    {:<20} used by {}", type_name, objects.join(", "));
        }
    }

    // ---------------------------------------------------------------
    // 7. OID tree direct access
    //
    // raw.tree() gives access to the OidTree with walk_oid(),
    // subtree(), all_nodes(), and longest_prefix_from(). The node
    // BTreeMap<u32, NodeId> children are in arc order, which matters
    // for ordered tree walks in an OID browser.
    // ---------------------------------------------------------------
    println!("\n=== OID tree ===");

    // Walk to a subtree and enumerate children with their arcs.
    let scalars_id = raw.resolve("rawScalars").unwrap();
    let scalars = raw.node(scalars_id);
    println!("  Children of {} (arc order):", scalars.name());
    for (arc, &child_id) in scalars.children() {
        let child = raw.node(child_id);
        let kind = child.kind();
        println!("    arc {arc}: {:<20} [{kind:?}]", child.name());
    }

    // Longest prefix match (for instance OID resolution).
    let instance_oid: mib_rs::Oid = "1.3.6.1.4.1.99990.1.1.42".parse().unwrap();
    let prefix_id = raw.longest_prefix_by_oid(&instance_oid);
    let prefix = raw.node(prefix_id);
    println!("\n  Longest prefix for {}: {}", instance_oid, prefix.name());

    // Effective module ownership for a node.
    if let Some(mod_id) = raw.effective_module(prefix_id) {
        println!("  Effective owner: {}", raw.module(mod_id).name());
    }

    // Depth-first subtree iteration via the tree.
    let tree = raw.tree();
    let subtree_count = tree.subtree(scalars_id).count();
    println!(
        "\n  Subtree size of {}: {} nodes",
        scalars.name(),
        subtree_count
    );

    // ---------------------------------------------------------------
    // 8. Cross-reference queries
    //
    // Mib-level queries that return IDs rather than handles, useful
    // for building reference indices.
    // ---------------------------------------------------------------
    println!("\n=== Cross-references ===");

    // Which modules define a given symbol?
    let definers = mib.modules_defining("rawDeviceName");
    println!("  'rawDeviceName' defined in:");
    for mod_id in &definers {
        println!("    {}", raw.module(*mod_id).name());
    }

    // Which modules import DisplayString?
    let importers = mib.modules_importing("DisplayString");
    println!("  'DisplayString' imported by:");
    for mod_id in &importers {
        println!("    {}", raw.module(*mod_id).name());
    }

    // Find all objects of a given base type.
    let counters = mib.objects_by_base_type(mib_rs::BaseType::Integer32);
    println!(
        "\n  Objects with effective base Integer32: {}",
        counters.len()
    );
    for id in counters.iter().take(5) {
        let obj = raw.object(*id);
        let mod_name = obj
            .module()
            .map(|mid| raw.module(mid).name())
            .unwrap_or("?");
        println!("    {}::{}", mod_name, obj.name());
    }

    // Find all objects using a specific named type.
    let by_type = mib.objects_by_type_name("RawName");
    println!("\n  Objects with type 'RawName':");
    for id in &by_type {
        println!("    {}", raw.object(*id).name());
    }

    // ---------------------------------------------------------------
    // 9. Combining handle and raw access
    //
    // The raw and handle APIs are views over the same data. You can
    // freely cross between them: handle.id() drops to raw, and
    // mib.*_by_id(id) lifts back to a handle. Use handles for
    // navigation, raw for bulk work and range access.
    // ---------------------------------------------------------------
    println!("\n=== Crossing between handle and raw ===");

    // Start with a handle, drop to raw for range info.
    let handle = mib.object("rawCount").unwrap();
    let id = handle.id(); // -> ObjectId
    let data = raw.object(id); // -> &ObjectData

    let (syn_line, _) =
        location(data.syntax_range().expect("SYNTAX range")).expect("valid SYNTAX range");
    let (acc_line, _) =
        location(data.access_range().expect("MAX-ACCESS range")).expect("valid MAX-ACCESS range");
    println!(
        "  {}: SYNTAX at line {}, MAX-ACCESS at line {}",
        handle.name(),
        syn_line,
        acc_line
    );

    // Start with raw, lift to handle for navigation.
    if let Some(type_id) = data.type_id() {
        let type_handle = mib.type_by_id(type_id);
        println!(
            "  Type chain: {} -> effective base {:?}",
            type_handle.name(),
            type_handle.effective_base()
        );
    }
}
