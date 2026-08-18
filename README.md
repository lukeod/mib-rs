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

- **SMIv1 and SMIv2 parsing**: Supports RFC 1155/1212/1215 and RFC 2578/2579/2580 constructs
- **Six-phase resolver**: Registration, imports, types, OIDs, semantics, and checks
- **OID tree**: Numeric and symbolic OID resolution, subtree walking, instance lookups
- **Type chains**: Inherited base types, display hints, enums, and constraints
- **Display-hint formatting**: RFC 2579 value formatting, numeric scaling, and octet-string rendering
- **Table support**: Rows, columns, indexes (including augmented/implied)
- **Diagnostics**: Configurable strictness levels with collected diagnostics instead of fail-fast
- **Lossless CST tooling**: Preserves source text and recovery regions in typed syntax nodes, with cursor context and source-safe semantic navigation
- **Resolution tracing**: Explains domain-specific symbol selection, import provenance, fallbacks, and unresolved references
- **Canonical SMIv2 writer**: Emits deterministic SMIv2 text from resolved modules
- **Parallel bulk loading**: Loading all discoverable modules uses available CPUs; selected-module loading and resolution are sequential
- **Embedded foundation modules**: RFC-derived source fallbacks, byte-synchronized with gomib and deliberately adapted, for SNMPv2-SMI, SNMPv2-TC, SNMPv2-CONF, RFC1155-SMI, and others
- **System path discovery**: Auto-detects net-snmp and libsmi MIB directories
- **Layered API**: Handle-based query API, low-level arena access, and public compiler pipeline

## Installation

```bash
cargo add mib-rs
```

Or add to your `Cargo.toml`:

```toml
[dependencies]
mib-rs = "0.9"
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
    REVISION "202603120000Z"
    DESCRIPTION "Initial version."
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

### Decode and encode table indexes

Compile table index metadata while the MIB is available, then retain the owned
codec in a runtime plan. Exact decoding rejects malformed, truncated, and
trailing arcs; canonical encoding checks value kinds and constraints.

```rust
use std::sync::Arc;
use mib_rs::{BoundIndexCodec, ConstraintMode, IndexSchema, IndexValue, IndexValueRef};

// Assume IF-MIB is already loaded into `mib`.
let codec = {
    let column = mib.object("ifDescr").expect("column exists");
    let schema = Arc::new(IndexSchema::compile(column).expect("valid INDEX metadata"));

    // Representable MIB concerns are retained rather than silently discarded.
    for issue in schema.issues() {
        eprintln!("schema issue: {issue:?}");
    }
    for component in schema.components() {
        for issue in component.issues() {
            eprintln!("{}: {issue:?}", component.name());
        }
    }

    BoundIndexCodec::for_object_oid(
        schema,
        column.node().expect("resolved column OID").oid(),
    )
    .expect("index suffix fits the instance-OID limit")
};

drop(mib); // the codec owns the metadata it needs

let decoded = codec.decode_exact(&[7], ConstraintMode::Enforce).unwrap();
assert_eq!(decoded.values(), &[IndexValue::Integer32(7)]);

let encoded = codec
    .encode_canonical([IndexValueRef::Integer32(7)])
    .unwrap();
assert_eq!(encoded.as_ref(), &[7]);
```

## CLI Tool

The optional `mib-rs` binary provides commands for working with MIBs:

```bash
cargo install mib-rs
```

### Global options

```bash
mib-rs -p /usr/share/snmp/mibs load IF-MIB    # custom MIB search path (-p is repeatable)
mib-rs -v load IF-MIB                          # debug logging (-vv for trace)
mib-rs --version                               # show version
```

When no `-p` paths are given, system MIB directories (net-snmp, libsmi) are used automatically.

### Commands

```bash
# Load and validate modules (omit names to load all available)
mib-rs load IF-MIB SNMPv2-MIB
mib-rs load --strict IF-MIB            # strict resolver mode
mib-rs load --permissive IF-MIB        # permissive resolver mode
mib-rs load --stats IF-MIB             # show detailed stats
mib-rs load --report quiet IF-MIB      # reporting level: silent, quiet, default, verbose

# Look up an OID or name
mib-rs get sysDescr
mib-rs get 1.3.6.1.2.1.1.1
mib-rs get sysDescr --full              # disable the default 200-character description limit
mib-rs get sysDescr -m SNMPv2-MIB      # only load specific modules

# Show a subtree
mib-rs get ifEntry --tree
mib-rs get ifEntry --tree --max-depth 2
mib-rs get ifEntry --max-depth 0        # root node only (--max-depth implies --tree)

# Search for nodes by pattern (case-insensitive, * and ? wildcards)
# Output format: MODULE::NAME OID KIND
mib-rs find "sys*"
mib-rs find "*Entry" --kind table       # filter by kind
mib-rs find "*Group" --kind group       # kinds: node, scalar, table, row, column,
                                        #   notification, group, compliance, capability,
                                        #   module-identity, object-identity
mib-rs find "if*" --type Integer32      # base-type filter (objects only)
mib-rs find "if*" --count               # print match count only
mib-rs find "if*" -m IF-MIB            # only load specific modules
mib-rs find "if*" --format json        # JSON output

# Inspect a symbol in detail
mib-rs inspect ifTable
mib-rs inspect IF-MIB::ifEntry

# Explain symbol resolution in a specific reference domain
mib-rs trace IF-MIB::ifDescr --domain object
mib-rs trace ifDescr --domain object -m IF-MIB --strictness strict
# Domains: type, oid, object, group-member, index, notification-object, conformance

# Emit canonical SMIv2 (stdout requires exactly one selected module)
mib-rs normalize IF-MIB > IF-MIB.mib
mib-rs normalize IF-MIB SNMPv2-MIB --output-dir normalized
mib-rs normalize IF-MIB --no-descriptions --no-conformance --no-sequences
# Omit module names with --output-dir to normalize all available user modules

# List available modules
mib-rs list
mib-rs list --count

# Show MIB search paths (custom and auto-discovered system paths)
mib-rs paths

# Lint with strict diagnostics
mib-rs lint IF-MIB
mib-rs lint IF-MIB --format json

# Export as JSON (diagnostics go to stderr)
mib-rs dump IF-MIB
mib-rs dump --strict IF-MIB
mib-rs dump --report silent IF-MIB     # suppress diagnostics on stderr
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `serde` | yes | Serde support and JSON export |
| `cli` | yes | CLI binary (`mib-rs`); enables `serde` |

To use the library without defaults:

```toml
[dependencies]
mib-rs = { version = "0.9", default-features = false }
```

## Minimum Supported Rust Version

This crate requires Rust 1.88 or later. The MSRV may be increased in minor releases.

## License

Licensed under either the [Apache License, Version 2.0](LICENSE-APACHE) or the
[MIT license](LICENSE-MIT), at your option.

## Contributing

Contributions are welcome. Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
