# mib-rs

[![CI](https://github.com/lukeod/mib-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeod/mib-rs/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/mib-rs.svg)](https://crates.io/crates/mib-rs)
[![Documentation](https://docs.rs/mib-rs/badge.svg)](https://docs.rs/mib-rs)
[![MSRV](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/)
[![License](https://img.shields.io/crates/l/mib-rs.svg)](#license)

SNMP MIB parser and resolver for Rust.

## Note

This library is not currently stable. While pre-v1.0, breaking changes may
occur in minor releases with no attempt to maintain backward compatibility.

## Features

- **Full SMI support**: Parses both SMIv1 (RFC 1155/1212) and SMIv2 (RFC 2578/2579/2580)
- **Multi-phase resolver**: Registration, imports, types, OIDs, and semantics
- **OID tree**: Numeric and symbolic OID resolution, subtree walking, instance lookups
- **Type chains**: Full type inheritance with effective base type, display hints, enums, ranges
- **Table support**: Rows, columns, indexes (including augmented/implied)
- **Diagnostics**: Configurable strictness levels with collected diagnostics instead of fail-fast
- **Parallel loading**: File I/O parallelized with rayon, sequential single-threaded resolution
- **Synthetic base modules**: SNMPv2-SMI, SNMPv2-TC, SNMPv2-CONF, RFC1155-SMI, and others built in
- **System path discovery**: Auto-detects net-snmp and libsmi MIB directories
- **Three API tiers**: High-level handles, low-level arena-backed raw data, and compiler pipeline access

## Installation

```bash
cargo add mib-rs
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
mib-rs = "0.1.2"
```

## Quick Start

### Load and query a MIB module

```rust
use mib_rs::{BaseType, Loader};

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
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example module."
    ::= { enterprises 99999 }

myName OBJECT-TYPE
    SYNTAX DisplayString (SIZE (0..255))
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A name."
    ::= { myMib 1 }

END
"#,
);

let mib = Loader::new()
    .source(source)
    .modules(["MY-MIB"])
    .load()
    .expect("should load");

let obj = mib.object("myName").expect("object exists");
assert_eq!(obj.name(), "myName");

let ty = obj.ty().expect("has type");
assert_eq!(ty.effective_base(), BaseType::OctetString);
```

### Load from system MIB directories

```rust
use mib_rs::Loader;

let mib = Loader::new()
    .system_paths()
    .modules(["IF-MIB", "SNMPv2-MIB"])
    .load()
    .expect("should load");

let node = mib.resolve_node("sysDescr").expect("should resolve");
println!("{}: {}", node.name(), mib.resolve_oid("sysDescr").unwrap());
```

### Resolve OIDs

```rust
use mib_rs::Loader;

let mib = Loader::new()
    .system_paths()
    .modules(["IF-MIB"])
    .load()
    .expect("should load");

// Symbolic to numeric
let oid = mib.resolve_oid("ifDescr").expect("should resolve");
println!("{}", oid); // 1.3.6.1.2.1.2.2.1.2

// Instance OIDs
let instance = mib.resolve_oid("ifDescr.7").expect("should resolve");
println!("{}", instance); // 1.3.6.1.2.1.2.2.1.2.7

// Reverse lookup
let node = mib.lookup_oid(&oid);
println!("{}", node.name()); // ifDescr
```

## CLI Tool

The optional `mib-rs` binary provides commands for working with MIBs:

```bash
cargo install mib-rs --features cli
```

```bash
# Load and validate modules
mib-rs load IF-MIB SNMPv2-MIB

# Look up an OID or name
mib-rs get sysDescr
mib-rs get 1.3.6.1.2.1.1.1

# Show a subtree
mib-rs get ifEntry --tree --max-depth 2

# Search for objects by pattern
mib-rs find "sys*"
mib-rs find "*Entry" --kind table

# List available modules
mib-rs list

# Lint with strict diagnostics
mib-rs lint IF-MIB

# Export as JSON
mib-rs dump IF-MIB
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `serde` | yes | Serde support and JSON export |
| `cli` | yes | CLI binary (`mib-rs`) |

To use the library without defaults:

```toml
[dependencies]
mib-rs = { version = "0.1", default-features = false }
```

## Minimum Supported Rust Version

This crate requires Rust 1.88 or later. The MSRV may be increased in minor releases.

## License

Licensed under the [MIT license](LICENSE).

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
