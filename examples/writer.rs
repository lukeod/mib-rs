//! Write a resolved module as canonical SMIv2.

use mib_rs::{Loader, writer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = mib_rs::source::memory(
        "DOC-EXAMPLE-MIB",
        include_bytes!("../tests/data/doc-example-mib.txt").as_slice(),
    );
    let mib = Loader::new()
        .source(source)
        .modules(["DOC-EXAMPLE-MIB"])
        .load()?;

    // The writer accepts any std::io::Write destination.
    writer::write(std::io::stdout().lock(), &mib, "DOC-EXAMPLE-MIB")?;
    Ok(())
}
