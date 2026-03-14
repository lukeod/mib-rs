//! Notifications, groups, and compliance statements.

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

    // -- Notifications --
    println!("=== Notifications ===");

    // Look up a notification by name.
    let notif = mib
        .notification("exStatusChange")
        .expect("notification exists");
    println!("  {}", notif.name());
    println!("    OID:         {}", notif.node().unwrap().oid());
    println!("    Status:      {:?}", notif.status());
    println!("    Description: {}", notif.description());
    println!("    Objects:");
    for obj in notif.objects() {
        println!("      {}", obj.name());
    }

    let notif2 = mib
        .notification("exIfStatusChange")
        .expect("notification exists");
    println!("\n  {}", notif2.name());
    println!("    OID:     {}", notif2.node().unwrap().oid());
    println!(
        "    Objects: {:?}",
        notif2.objects().map(|o| o.name()).collect::<Vec<_>>()
    );

    // -- Enumerate all notifications in the user module --
    println!("\n  All notifications:");
    for notif in mib.notifications() {
        if notif.module().map(|m| m.name()) == Some("EXAMPLE-FULL-MIB") {
            println!("    {}", notif.name());
        }
    }

    // -- Object Groups --
    println!("\n=== Object Groups ===");
    let group = mib.group("exScalarGroup").expect("group exists");
    println!("  {}", group.name());
    println!("    OID:         {}", group.node().unwrap().oid());
    println!("    Status:      {:?}", group.status());
    println!("    Description: {}", group.description());
    println!(
        "    Is notification group: {}",
        group.is_notification_group()
    );
    println!("    Members:");
    for member in group.members() {
        println!("      {}", member.name());
    }

    // -- Notification Group --
    let ngroup = mib.group("exNotifGroup").expect("group exists");
    println!("\n  {}", ngroup.name());
    println!(
        "    Is notification group: {}",
        ngroup.is_notification_group()
    );
    println!("    Members:");
    for member in ngroup.members() {
        println!("      {}", member.name());
    }

    // -- Compliance --
    let compliance = mib
        .compliance("exBasicCompliance")
        .expect("compliance exists");
    println!("\n=== Compliance ===");
    println!("  {}", compliance.name());
    println!("    OID:         {}", compliance.node().unwrap().oid());
    println!("    Status:      {:?}", compliance.status());
    println!("    Description: {}", compliance.description());
    println!("    MODULE clauses: {}", compliance.modules().len());

    // -- Node-level cross references --
    // Nodes can tell you what's attached to them.
    let node = mib.resolve_node("exStatusChange").unwrap();
    println!("\n=== Node cross-references ===");
    println!("  Node: {}", node.name());
    println!("    Has notification: {}", node.notification().is_some());
    println!("    Has object:       {}", node.object().is_some());
    println!("    Has group:        {}", node.group().is_some());

    let node = mib.resolve_node("exScalarGroup").unwrap();
    println!("  Node: {}", node.name());
    println!("    Has group:        {}", node.group().is_some());

    let node = mib.resolve_node("exBasicCompliance").unwrap();
    println!("  Node: {}", node.name());
    println!("    Has compliance:   {}", node.compliance().is_some());
}
