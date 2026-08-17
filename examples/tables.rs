//! Table navigation: rows, columns, indexes, and object kind predicates.

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

    // -- Find all tables --
    println!("=== Tables ===");
    for table in mib.tables() {
        println!("  {} ({})", table.name(), table.node().unwrap().oid());
    }

    // -- Table structure --
    let table = mib.object("exIfTable").unwrap();
    println!("\n=== exIfTable structure ===");
    println!("  Is table:  {}", table.is_table());
    println!("  Kind:      {:?}", table.kind());

    // Get the row entry
    let row = table.row().expect("table should have a row");
    println!("\n  Row: {}", row.name());
    println!("    Is row:  {}", row.is_row());

    // Navigate back to the table from the row
    let back = row.table().expect("row should reference table");
    assert_eq!(back.name(), table.name());

    // -- Columns --
    println!("\n  Columns:");
    for col in table.columns() {
        let ty = col.ty().map(|t| t.name().to_string()).unwrap_or_default();
        println!(
            "    {:<20} {:?} type={:<20} index={}",
            col.name(),
            col.access(),
            ty,
            col.is_index(),
        );
        assert!(col.is_column());
    }

    // Navigate from a column back to its row and table.
    let col = mib.object("exIfName").unwrap();
    let col_row = col.row().expect("column should have a row");
    let col_table = col.table().expect("column should have a table");
    println!(
        "\n  exIfName -> row={}, table={}",
        col_row.name(),
        col_table.name()
    );

    // -- Indexes --
    println!("\n=== Indexes ===");
    let indexes: Vec<_> = row.effective_indexes().collect();
    for idx in &indexes {
        let obj = idx.object().expect("index object");
        let ty = idx.ty().expect("index type");
        println!("  {}", idx.name());
        println!("    Object:   {}", obj.name());
        println!(
            "    Type:     {} (base={:?})",
            ty.name(),
            ty.effective_base()
        );
        println!("    Implied:  {}", idx.implied());
        println!("    Encoding: {:?}", idx.encoding());
        println!("    Row:      {}", idx.row().name());
    }

    // -- All scalars --
    println!("\n=== Scalars ===");
    for scalar in mib.scalars() {
        let ty_name = scalar
            .ty()
            .map(|t| t.name().to_string())
            .unwrap_or_default();
        println!(
            "  {:<20} {:<20} {:?}",
            scalar.name(),
            ty_name,
            scalar.access(),
        );
        assert!(scalar.is_scalar());
    }

    // -- All rows --
    println!("\n=== Rows ===");
    for row in mib.rows() {
        let idx_names: Vec<_> = row
            .effective_indexes()
            .map(|i| i.name().to_string())
            .collect();
        println!("  {:<20} indexes=[{}]", row.name(), idx_names.join(", "));
    }

    // -- All columns --
    println!("\n=== All columns ===");
    for col in mib.columns() {
        println!(
            "  {:<20} table={}",
            col.name(),
            col.table()
                .map(|t| t.name().to_string())
                .unwrap_or_default(),
        );
    }

    // -- Object kind filtering --
    println!("\n=== Object counts by kind ===");
    println!("  Tables:  {}", mib.tables().count());
    println!("  Rows:    {}", mib.rows().count());
    println!("  Columns: {}", mib.columns().count());
    println!("  Scalars: {}", mib.scalars().count());
}
