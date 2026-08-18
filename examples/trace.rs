//! Explain how the resolver selects a symbol.

use mib_rs::Loader;
use mib_rs::mib::ResolutionOutcome;
use mib_rs::types::ResolutionDomain;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source = mib_rs::source::memory(
        "DOC-EXAMPLE-MIB",
        include_bytes!("../tests/data/doc-example-mib.txt").as_slice(),
    );
    let mib = Loader::new()
        .source(source)
        .modules(["DOC-EXAMPLE-MIB"])
        .load()?;

    // A qualified query establishes the module scope. The domain selects the
    // resolver rules for this use of the symbol.
    let trace = mib.trace_symbol(
        "DOC-EXAMPLE-MIB::DisplayString",
        None,
        ResolutionDomain::Type,
    )?;

    println!("Query:   {}", trace.query);
    println!("Symbol:  {}", trace.symbol);
    println!("Domain:  {}", trace.domain);
    println!("Outcome: {:?}", trace.outcome);
    assert_eq!(trace.outcome, ResolutionOutcome::Resolved);

    let target = trace.target.expect("a resolved trace should have a target");
    println!(
        "Target:  {}::{} ({})",
        target.candidate.module_name, trace.symbol, target.strategy
    );

    if let Some(import) = trace.import {
        println!("Import:  {:?}", import.mode);
    }

    for candidate in trace.candidates {
        println!(
            "Candidate: {}::{}, kind={}, applicable={}",
            candidate.module_name, trace.symbol, candidate.kind, candidate.applicable
        );
    }

    Ok(())
}
