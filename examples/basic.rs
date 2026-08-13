//! Load a MIB from memory, query objects, and display module metadata.

use mib_rs::{BaseType, Loader};

fn main() {
    // Load from an in-memory MIB source.
    let source = mib_rs::source::memory(
        "MY-MIB",
        r#"MY-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    DisplayString
        FROM SNMPv2-TC;

myMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example Corp"
    CONTACT-INFO "support@example.com"
    DESCRIPTION "A basic example module."
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
    ::= { enterprises 99999 }

myScalars OBJECT IDENTIFIER ::= { myMib 1 }

myName OBJECT-TYPE
    SYNTAX DisplayString (SIZE (0..255))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A name."
    ::= { myScalars 1 }

myCount OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "An integer count."
    ::= { myScalars 2 }

END
"#,
    );

    let mib = Loader::new()
        .source(source)
        .modules(["MY-MIB"])
        .load()
        .expect("should load");

    // -- Module metadata --
    let module = mib.module("MY-MIB").expect("module exists");
    println!("Module:   {}", module.name());
    println!("Language: {:?}", module.language());
    println!("Is base:  {}", module.is_base());
    if let Some(oid) = module.oid() {
        println!("OID:      {oid}");
    }

    // Module-level metadata from MODULE-IDENTITY.
    println!("Organization: {}", module.organization());
    println!("Description:  {}", module.description());
    println!("Last updated: {}", module.last_updated());
    for rev in module.revisions() {
        println!("  Revision: {} - {}", rev.date, rev.description);
    }

    // -- Object lookup by name --
    let obj = mib.object("myName").expect("object exists");
    println!("\nObject: {}", obj.name());
    println!("  Status:      {:?}", obj.status());
    println!("  Access:      {:?}", obj.access());
    println!("  Description: {}", obj.description());
    println!("  Kind:        {:?}", obj.kind());

    // -- Type information --
    let ty = obj.ty().expect("has type");
    println!("  Type name:   {}", ty.name());
    println!("  Base type:   {:?}", ty.effective_base());
    assert_eq!(ty.effective_base(), BaseType::OctetString);

    // -- Iterate all objects in the module --
    println!("\nAll objects in {}:", module.name());
    for obj in module.objects() {
        let oid = obj.node().oid();
        let type_name = obj
            .ty()
            .map(|t| t.name().to_string())
            .unwrap_or_else(|| "-".into());
        println!("  {:<20} {:<24} {}", obj.name(), oid, type_name);
    }

    // -- Iterate all types in the module --
    println!("\nAll types in {}:", module.name());
    for ty in module.types() {
        println!(
            "  {:<20} base={:?}  tc={}",
            ty.name(),
            ty.effective_base(),
            ty.is_textual_convention()
        );
    }

    // -- Iterate all nodes in the module --
    println!("\nAll nodes in {}:", module.name());
    for node in module.nodes() {
        println!("  {:<20} {}", node.name(), node.oid());
    }

    // -- Count summary --
    println!("\nSummary:");
    println!("  Modules: {}", mib.modules().count());
    println!("  Objects: {}", mib.objects().count());
    println!("  Types:   {}", mib.types().count());
    println!("  Scalars: {}", mib.scalars().count());
    println!("  Tables:  {}", mib.tables().count());

    // -- Diagnostics --
    println!("  Errors:  {}", mib.has_errors());
    if !mib.diagnostics().is_empty() {
        println!("  Diagnostics:");
        for d in mib.diagnostics() {
            println!("    {d}");
        }
    }
}
