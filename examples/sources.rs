//! Source types: in-memory modules, directory sources, chaining,
//! and module listing.

use mib_rs::Loader;

fn main() {
    // -- Single in-memory module --
    println!("=== Memory source (single) ===");
    let source = mib_rs::source::memory(
        "MEM-MIB",
        br#"MEM-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, enterprises
        FROM SNMPv2-SMI;

memMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "In-memory module."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 11111 }

END
"#
        .as_slice(),
    );

    let mib = Loader::new()
        .source(source)
        .modules(["MEM-MIB"])
        .load()
        .expect("should load");
    println!("  Loaded: {}", mib.module("MEM-MIB").unwrap().name());

    // -- Multiple in-memory modules --
    println!("\n=== Memory source (multiple) ===");
    let source = mib_rs::source::memory_modules(vec![
        (
            "MULTI-A-MIB",
            br#"MULTI-A-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, enterprises
        FROM SNMPv2-SMI;

multiAMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Module A."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 22221 }
END
"#
            .as_slice(),
        ),
        (
            "MULTI-B-MIB",
            br#"MULTI-B-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, enterprises
        FROM SNMPv2-SMI;

multiBMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Module B."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 22222 }
END
"#
            .as_slice(),
        ),
    ]);

    let mib = Loader::new()
        .source(source)
        .modules(["MULTI-A-MIB", "MULTI-B-MIB"])
        .load()
        .expect("should load");

    for module in mib.user_modules() {
        println!("  Loaded: {}", module.name());
    }

    // -- Source chaining --
    // chain() combines multiple sources; first match wins.
    println!("\n=== Chained sources ===");
    let primary = mib_rs::source::memory(
        "PRIMARY-MIB",
        br#"PRIMARY-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, enterprises
        FROM SNMPv2-SMI;

primaryMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Primary source."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 33331 }
END
"#
        .as_slice(),
    );

    let fallback = mib_rs::source::memory(
        "FALLBACK-MIB",
        br#"FALLBACK-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, enterprises
        FROM SNMPv2-SMI;

fallbackMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Fallback source."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 33332 }
END
"#
        .as_slice(),
    );

    let chained = mib_rs::source::chain(vec![primary, fallback]);

    let mib = Loader::new()
        .source(chained)
        .modules(["PRIMARY-MIB", "FALLBACK-MIB"])
        .load()
        .expect("should load");

    for module in mib.user_modules() {
        println!("  Loaded: {}", module.name());
    }

    // -- Module listing from a source --
    // Sources can list what modules they contain.
    println!("\n=== Listing modules from a source ===");
    let source = mib_rs::source::memory_modules(vec![
        ("LIST-A", b"LIST-A DEFINITIONS ::= BEGIN END".as_slice()),
        ("LIST-B", b"LIST-B DEFINITIONS ::= BEGIN END".as_slice()),
        ("LIST-C", b"LIST-C DEFINITIONS ::= BEGIN END".as_slice()),
    ]);

    let modules = source.list_modules().expect("should list");
    println!("  Available modules: {}", modules.join(", "));

    // -- FindResult gives you the raw content and path --
    let result = source.find("LIST-A").expect("should not error");
    if let Some(found) = result {
        println!(
            "  Found LIST-A: path={:?}, size={} bytes",
            found.path,
            found.content.len()
        );
    }

    // -- Loading without specifying modules loads all available --
    println!("\n=== Load all available modules ===");
    let source = mib_rs::source::memory_modules(vec![
        (
            "ALL-A-MIB",
            br#"ALL-A-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, enterprises FROM SNMPv2-SMI;
allAMib MODULE-IDENTITY LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example" CONTACT-INFO "Example"
    DESCRIPTION "A."
    REVISION "202603120000Z" DESCRIPTION "Initial version."
    ::= { enterprises 44441 }
END
"#
            .as_slice(),
        ),
        (
            "ALL-B-MIB",
            br#"ALL-B-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, enterprises FROM SNMPv2-SMI;
allBMib MODULE-IDENTITY LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example" CONTACT-INFO "Example"
    DESCRIPTION "B."
    REVISION "202603120000Z" DESCRIPTION "Initial version."
    ::= { enterprises 44442 }
END
"#
            .as_slice(),
        ),
    ]);

    let mib = Loader::new()
        .source(source)
        .load()
        .expect("should load all");

    let user_modules: Vec<_> = mib.user_modules().collect();
    println!("  Loaded {} user modules", user_modules.len());
    for m in &user_modules {
        println!("    {}", m.name());
    }

    // -- Directory source (commented out - requires actual MIB files on disk) --
    // let source = mib_rs::source::dir("/usr/share/snmp/mibs").expect("dir exists");
    // let mib = Loader::new()
    //     .source(source)
    //     .modules(["IF-MIB"])
    //     .load()
    //     .expect("should load");

    // -- System path auto-discovery (commented out - requires net-snmp/libsmi installed) --
    // let mib = Loader::new()
    //     .system_paths()
    //     .modules(["IF-MIB", "SNMPv2-MIB"])
    //     .load()
    //     .expect("should load");
}
