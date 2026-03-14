//! SNMP MIB parsing, resolution, query, and tooling APIs.
//!
//! # What is a MIB?
//!
//! A MIB (Management Information Base) is a text file that describes the
//! structure of data available from an SNMP-managed device. Each piece of
//! data (a counter, a name, a status flag, a table row) is identified by an
//! OID (Object Identifier), a dotted-decimal path like `1.3.6.1.2.1.1.1`.
//! MIB files give those numeric OIDs human-readable names, types, and
//! descriptions, so instead of `1.3.6.1.2.1.1.1` you can say `sysDescr`.
//!
//! MIBs are written in a language called SMI (Structure of Management
//! Information), which has two versions: SMIv1 (RFC 1155/1212) and SMIv2
//! (RFC 2578/2579/2580). This crate handles both transparently.
//!
//! # API Tiers
//!
//! This crate exposes three intentional API tiers:
//!
//! - **High-level handles** - start with [`Loader`] and navigate the
//!   resolved model with [`Mib`], [`Module`], [`Node`], [`Object`], and [`Type`].
//! - **Low-level raw data** - call [`Mib::raw()`] to work with stable ids,
//!   arena-backed records, and the OID tree directly. This tier exists for
//!   tooling such as linters, language servers, exporters, and editor
//!   integrations. See the [`raw`] module.
//! - **Compiler pipeline** - [`ast`], [`parser`], [`lower`], [`ir`], and
//!   [`token`] expose pre-resolution stages for callers that need syntax-aware
//!   analysis or diagnostics before full resolution. See the [`compile`] module.
//!
//! Most library code should stay in the handle-oriented high-level API. Drop to
//! [`raw`] or the compiler pipeline only when you need that additional control.
//!
//! # Loading MIBs
//!
//! Use [`Loader`] to configure sources, select modules, and run the pipeline:
//!
//! ```rust
//! use mib_rs::{BaseType, Loader};
//!
//! fn example_mib() -> mib_rs::Mib {
//!     let source = mib_rs::source::memory(
//!         "DOC-EXAMPLE-MIB",
//!         r#"DOC-EXAMPLE-MIB DEFINITIONS ::= BEGIN
//! IMPORTS
//!     MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
//!         FROM SNMPv2-SMI
//!     TEXTUAL-CONVENTION, DisplayString
//!         FROM SNMPv2-TC;
//!
//! docExampleMib MODULE-IDENTITY
//!     LAST-UPDATED "202603120000Z"
//!     ORGANIZATION "Example"
//!     CONTACT-INFO "Example"
//!     DESCRIPTION "Example module used in crate docs."
//!     ::= { enterprises 99999 }
//!
//! DocName ::= TEXTUAL-CONVENTION
//!     DISPLAY-HINT "255a"
//!     STATUS current
//!     DESCRIPTION "Example display string type."
//!     SYNTAX DisplayString (SIZE (0..255))
//!
//! docScalars OBJECT IDENTIFIER ::= { docExampleMib 1 }
//! docTables OBJECT IDENTIFIER ::= { docExampleMib 2 }
//!
//! docDeviceName OBJECT-TYPE
//!     SYNTAX DocName
//!     MAX-ACCESS read-only
//!     STATUS current
//!     DESCRIPTION "A scalar object."
//!     ::= { docScalars 1 }
//!
//! docTable OBJECT-TYPE
//!     SYNTAX SEQUENCE OF DocEntry
//!     MAX-ACCESS not-accessible
//!     STATUS current
//!     DESCRIPTION "Example table."
//!     ::= { docTables 1 }
//!
//! docEntry OBJECT-TYPE
//!     SYNTAX DocEntry
//!     MAX-ACCESS not-accessible
//!     STATUS current
//!     DESCRIPTION "Example row."
//!     INDEX { docIndex }
//!     ::= { docTable 1 }
//!
//! DocEntry ::= SEQUENCE {
//!     docIndex Integer32,
//!     docDescr DisplayString
//! }
//!
//! docIndex OBJECT-TYPE
//!     SYNTAX Integer32 (1..2147483647)
//!     MAX-ACCESS not-accessible
//!     STATUS current
//!     DESCRIPTION "Example index."
//!     ::= { docEntry 1 }
//!
//! docDescr OBJECT-TYPE
//!     SYNTAX DisplayString
//!     MAX-ACCESS read-only
//!     STATUS current
//!     DESCRIPTION "Example column."
//!     ::= { docEntry 2 }
//!
//! END
//! "#,
//!     );
//!
//!     Loader::new()
//!         .source(source)
//!         .modules(["DOC-EXAMPLE-MIB"])
//!         .load()
//!         .expect("example MIB should load")
//! }
//!
//! let mib = example_mib();
//! let object = mib.object("docDeviceName").expect("object should exist");
//! let ty = object.ty().expect("object should have a type");
//!
//! assert_eq!(object.name(), "docDeviceName");
//! assert_eq!(ty.name(), "DocName");
//! assert_eq!(ty.effective_base(), BaseType::OctetString);
//! assert_eq!(ty.effective_display_hint(), "255a");
//! ```
//!
//! # OIDs and Resolution
//!
//! Every named element in a MIB has an OID, a path through a global tree
//! shared by all SNMP devices. OIDs are written as dotted decimal
//! (`1.3.6.1.2.1.1.1`) or symbolically (`sysDescr`). The tree is
//! hierarchical: `enterprises` is `1.3.6.1.4.1`, and a vendor's subtree
//! hangs beneath that.
//!
//! **Instance OIDs** extend a base OID with a suffix that identifies a
//! specific value. For a scalar like `sysDescr`, the instance is always
//! `sysDescr.0`. For table columns, the suffix encodes the row's index
//! values, e.g. `ifDescr.7` for interface 7.
//!
//! This crate resolves both directions: name to numeric OID, and numeric
//! OID back to its closest named node.
//!
//! ```rust
//! fn example_mib() -> mib_rs::Mib {
//!     let source = mib_rs::source::memory(
//!         "DOC-EXAMPLE-MIB",
//!         include_bytes!("../tests/data/doc-example-mib.txt").as_slice(),
//!     );
//!
//!     mib_rs::Loader::new()
//!         .source(source)
//!         .modules(["DOC-EXAMPLE-MIB"])
//!         .load()
//!         .expect("example MIB should load")
//! }
//!
//! let mib = example_mib();
//!
//! let column_oid = mib.resolve_oid("docDescr").expect("OID should resolve");
//! assert_eq!(column_oid.to_string(), "1.3.6.1.4.1.99999.2.1.1.2");
//!
//! let node = mib
//!     .exact_node_by_oid(&column_oid)
//!     .expect("exact node should exist");
//! assert_eq!(node.name(), "docDescr");
//!
//! let instance_node = mib
//!     .resolve_node("docDescr.7")
//!     .expect("instance OID should resolve to its base node");
//! assert_eq!(instance_node.name(), "docDescr");
//!
//! let instance_oid = mib.resolve_oid("docDescr.7").expect("instance OID should resolve");
//! assert_eq!(instance_oid.to_string(), "1.3.6.1.4.1.99999.2.1.1.2.7");
//! assert_eq!(mib.lookup_oid(&instance_oid).name(), "docDescr");
//! assert_eq!(mib.lookup_oid(&"1.3.6.1.4.1.99999.2.1.1.2.99".parse().unwrap()).name(), "docDescr");
//! ```
//!
//! # Tables and Indexes
//!
//! SNMP models tabular data as three nested objects:
//!
//! - A **table** (`SEQUENCE OF`) is a container, not directly readable.
//! - A **row** (entry) represents one row, also not directly readable.
//!   It declares which columns are **index** columns, whose values
//!   together form the instance suffix that identifies each row.
//! - **Columns** are the actual readable/writable values. Each column's
//!   full OID is the column OID plus the index suffix.
//!
//! For example, `ifTable` contains `ifEntry` rows indexed by `ifIndex`.
//! The column `ifDescr` for interface 7 has OID `ifDescr.7`.
//!
//! Use [`Object::is_table`], [`Object::is_row`], [`Object::is_column`],
//! and [`Object::is_scalar`] to distinguish these, or use the filtered
//! iterators like [`Mib::table_objects`] and [`Mib::scalar_objects`].
//!
//! ```rust
//! fn example_mib() -> mib_rs::Mib {
//!     let source = mib_rs::source::memory(
//!         "DOC-EXAMPLE-MIB",
//!         include_bytes!("../tests/data/doc-example-mib.txt").as_slice(),
//!     );
//!
//!     mib_rs::Loader::new()
//!         .source(source)
//!         .modules(["DOC-EXAMPLE-MIB"])
//!         .load()
//!         .expect("example MIB should load")
//! }
//!
//! let mib = example_mib();
//! let table = mib.object("docTable").expect("table should exist");
//! let row = table.row().expect("table should have a row");
//!
//! let column_names: Vec<_> = table.columns().map(|col| col.name()).collect();
//! assert_eq!(column_names, vec!["docIndex", "docDescr"]);
//!
//! let indexes: Vec<_> = row.effective_indexes().collect();
//! assert_eq!(indexes.len(), 1);
//! assert_eq!(indexes[0].row().name(), "docEntry");
//! let index_object = indexes[0].object().expect("index object");
//! let index_type = indexes[0].ty().expect("index type");
//! assert_eq!(index_object.name(), "docIndex");
//! assert_eq!(indexes[0].name(), "docIndex");
//! assert_eq!(index_type.name(), "Integer32");
//! ```
//!
//! # Modules
//!
//! A MIB file contains one module (e.g. `IF-MIB`, `SNMPv2-MIB`). Modules
//! import symbols from other modules, so loading one module typically
//! pulls in its dependencies automatically.
//!
//! Seven **base modules** (`SNMPv2-SMI`, `SNMPv2-TC`, `SNMPv2-CONF`,
//! `RFC1155-SMI`, `RFC1065-SMI`, `RFC-1212`, `RFC-1215`) are built in
//! and always available. These define the fundamental types and OID
//! roots that all other MIBs build on. You can identify them with
//! [`Module::is_base`].
//!
//! Use [`Module`] handles to scope lookups and iteration to a single
//! module:
//!
//! ```rust
//! fn example_mib() -> mib_rs::Mib {
//!     let source = mib_rs::source::memory(
//!         "DOC-EXAMPLE-MIB",
//!         include_bytes!("../tests/data/doc-example-mib.txt").as_slice(),
//!     );
//!
//!     mib_rs::Loader::new()
//!         .source(source)
//!         .modules(["DOC-EXAMPLE-MIB"])
//!         .load()
//!         .expect("example MIB should load")
//! }
//!
//! let mib = example_mib();
//! let module = mib.module("DOC-EXAMPLE-MIB").expect("module should exist");
//!
//! assert_eq!(module.object("docDeviceName").unwrap().module(), Some(module));
//!
//! let object_names: Vec<_> = module.objects().map(|obj| obj.name()).collect();
//! assert!(object_names.contains(&"docTable"));
//! assert!(object_names.contains(&"docDescr"));
//!
//! let type_names: Vec<_> = module.types().map(|ty| ty.name()).collect();
//! assert!(type_names.contains(&"DocName"));
//! ```
//!
//! # Query Formats
//!
//! Once a MIB is loaded, you can look up nodes and OIDs using several
//! formats. Qualified names (`MODULE::name`) are useful when multiple
//! modules define the same name. [`Mib::resolve_oid`],
//! [`Mib::resolve_node`], and [`Mib::resolve`] all accept these forms:
//!
//! | Form | Example | Description |
//! |------|---------|-------------|
//! | Plain name | `sysDescr` | Looks up by object/node name across all modules |
//! | Qualified name | `SNMPv2-MIB::sysDescr` | Scoped to a specific module |
//! | Instance OID | `ifDescr.7` | Name with numeric suffix appended |
//! | Numeric OID | `1.3.6.1.2.1.1.1` | Dotted decimal, leading dot optional |
//!
//! For instance OIDs (both symbolic and numeric), [`Mib::resolve_node`] returns
//! the deepest matching tree node, while [`Mib::resolve_oid`] returns the full
//! numeric OID with the suffix included.
//!
//! [`Mib::format_oid`] converts a numeric [`Oid`] back to `MODULE::name.suffix`
//! form using longest-prefix matching.
//!
//! # Sources
//!
//! Sources tell the loader where to find MIB files. For testing and
//! embedding, use in-memory sources. For production use, point at
//! directories on disk or use system path auto-discovery to find MIBs
//! installed by net-snmp or libsmi. The [`source`] module has several
//! constructors:
//!
//! | Constructor | Description |
//! |-------------|-------------|
//! | [`source::dir`] | Recursively indexes a directory tree on disk |
//! | [`source::dirs`] | Chains multiple directory trees |
//! | [`source::memory`] | Single in-memory module (for tests or embedding) |
//! | [`source::memory_modules`] | Multiple in-memory modules |
//! | [`source::chain`] | Combines multiple sources; first match wins |
//!
//! [`Loader::system_paths`](load::Loader::system_paths) auto-discovers
//! net-snmp and libsmi MIB directories from config files and environment
//! variables (see [`searchpath`]).
//!
//! Module names are derived from file content (scanning for `DEFINITIONS`
//! headers), not from filenames. Files are matched by extension using
//! [`source::DEFAULT_EXTENSIONS`] (`.mib`, `.smi`, `.txt`, `.my`, or no
//! extension).
//!
//! # Type Introspection
//!
//! SMI types form parent chains. A MIB might define `HostName` as a
//! refinement of `DisplayString`, which is itself a textual convention
//! over `OCTET STRING`. Each link in the chain can add constraints
//! (size limits, value ranges), a display hint (how to render the value
//! as text), or enumeration labels.
//!
//! Each [`Type`] handle exposes two families of accessors:
//!
//! - **Direct** (`base`, `display_hint`, `enums`, `sizes`, `ranges`) -
//!   return only what this specific type declares. These are empty/None
//!   if the type inherits everything from its parent.
//! - **Effective** (`effective_base`, `effective_display_hint`,
//!   `effective_enums`, `effective_sizes`, `effective_ranges`) - walk up
//!   the parent chain and return the first non-empty value. These give
//!   you the "resolved" answer.
//!
//! **In most cases, use the `effective_*` methods.** They give you the
//! answer you actually want: "what base type does this ultimately
//! represent?", "how should I format this value?", "what are the valid
//! enum labels?". The direct methods are mainly useful when you need to
//! know exactly where in the chain a property was introduced, for
//! instance when building a MIB browser that shows the full type
//! derivation.
//!
//! | Method | Description |
//! |--------|-------------|
//! | [`Type::base`] | Directly assigned base type (may be `Unknown` for derived types) |
//! | [`Type::effective_base`] | Resolved base type - use this one |
//! | [`Type::parent`] | Immediate parent type (if derived) |
//! | [`Type::display_hint`] | This type's own DISPLAY-HINT (often empty) |
//! | [`Type::effective_display_hint`] | First non-empty hint in the chain - use this one |
//! | [`Type::enums`] | This type's own enum values |
//! | [`Type::effective_enums`] | First non-empty enums in the chain - use this one |
//! | [`Type::sizes`] / [`Type::ranges`] | This type's own constraints |
//! | [`Type::effective_sizes`] / [`Type::effective_ranges`] | Inherited constraints - use these |
//! | [`Type::is_textual_convention`] | Whether defined as a TEXTUAL-CONVENTION |
//!
//! Convenience predicates: [`Type::is_counter`], [`Type::is_gauge`],
//! [`Type::is_string`], [`Type::is_enumeration`], [`Type::is_bits`].
//! These all use the effective base type internally.
//!
//! Objects expose the same effective accessors directly (e.g.
//! [`Object::effective_display_hint`], [`Object::effective_enums`]) so
//! you don't need to go through the type handle for common lookups.
//!
//! # Diagnostics and Configuration
//!
//! Real-world MIB files frequently contain errors, vendor-specific
//! extensions, or references to modules you don't have. Rather than
//! failing on the first problem, this library collects diagnostics and
//! continues, producing as much useful output as possible. After
//! loading, check [`Mib::has_errors`] and inspect [`Mib::diagnostics`]
//! for details.
//!
//! There are two independent knobs that control loading behavior.
//! They can seem redundant at first ("don't both of them control how
//! strict loading is?"), but they operate at different levels.
//!
//! Think of it like a Rust analogy: [`ResolverStrictness`] is like
//! controlling how `use` imports are resolved. In Rust, `use foo::Bar`
//! must name the exact path. In MIBs, imports work similarly - a module
//! declares `IMPORTS DisplayString FROM SNMPv2-TC`. But many real-world
//! MIBs get this wrong: they import from the wrong module, or don't
//! declare imports at all. `ResolverStrictness` controls whether the
//! resolver gives up on those broken imports or tries to find the
//! symbol anyway - like if `rustc` had a mode where it would search
//! all your dependencies for a matching type name when an import fails.
//!
//! [`DiagnosticConfig`], on the other hand, is like compiler warnings
//! and `-Werror`. It controls what gets reported across the entire
//! pipeline (lexing, parsing, and resolution), and whether problems
//! cause `load()` to fail. It doesn't change what gets resolved.
//!
//! The key tradeoff with `ResolverStrictness` is **correctness vs
//! completeness**. The more permissive you go, the more things get
//! resolved, but the higher the risk of incorrect results. At
//! `Permissive`, the resolver falls back to searching all loaded
//! modules for a matching symbol name. If multiple modules define a
//! symbol with the same name, you're essentially guessing which one
//! was intended. At `Strict`, everything must be explicitly imported
//! from the right module, so if it resolves, it's correct.
//!
//! ## ResolverStrictness - what the resolver attempts
//!
//! [`ResolverStrictness`] controls how aggressively the resolver tries
//! to recover when it can't find a symbol through explicit imports. Set
//! via [`Loader::resolver_strictness`](load::Loader::resolver_strictness).
//!
//! | Level | Behavior | Correctness risk | When to use |
//! |-------|----------|-----------------|-------------|
//! | `Strict` | No fallbacks. Symbols must be found via explicit imports. | Lowest - if it resolves, the import was correct. | Validating MIBs for correctness, linting, CI checks. |
//! | `Normal` (default) | Constrained fallbacks: searches well-known base modules (SNMPv2-SMI, SNMPv2-TC, RFC1155-SMI), global OID roots, and import aliases. | Low - fallbacks are limited to safe, unambiguous cases. | General use. Handles sloppy imports that are obviously resolvable. |
//! | `Permissive` | All fallbacks, including searching every loaded module for the symbol by name. | Higher - if two modules define `FooStatus`, the resolver picks one. | Loading badly-written vendor MIBs that you can't fix. |
//!
//! **Which should I use?** Start with `Normal` (the default). If you
//! get unresolved-reference diagnostics, it's usually better to fix
//! the MIB file directly (correcting the `IMPORTS` statement to name
//! the right source module) rather than reaching for `Permissive`.
//! MIB files are plain text, and import fixes are usually obvious from
//! the diagnostic message. Reserve `Permissive` for cases where you
//! can't modify the MIB files, such as vendor-supplied MIBs loaded
//! from a read-only path. `Strict` is useful for validation tooling
//! or CI, where you want broken imports to surface as unresolved
//! references rather than being silently fixed up.
//!
//! ## DiagnosticConfig - what gets reported
//!
//! [`DiagnosticConfig`] controls which diagnostics are collected and
//! which severity level causes `load()` to fail. This is purely about
//! reporting - it does not change what the resolver does. Set via
//! [`Loader::diagnostic_config`](load::Loader::diagnostic_config).
//!
//! It has four preset constructors:
//!
//! | Preset | What's reported | `load()` fails at | When to use |
//! |--------|-----------------|-------------------|-------------|
//! | [`DiagnosticConfig::verbose()`] | Everything (style, info, warnings) | Severe | Debugging MIB issues, understanding what the resolver did. |
//! | [`DiagnosticConfig::default()`] | Minor and above | Severe | General use. |
//! | [`DiagnosticConfig::quiet()`] | Errors and above only | Severe | Production code that just wants to know about real problems. |
//! | [`DiagnosticConfig::silent()`] | Nothing | Fatal only | When you don't care about diagnostics at all and want `load()` to succeed unless something is truly broken. |
//!
//! **Which should I use?** The default is fine for most cases. Use
//! `quiet()` in production if you don't want to surface minor issues
//! to users. Use `silent()` when loading untrusted or messy vendor
//! MIBs where you just want whatever data you can get. Use `verbose()`
//! when diagnosing why something isn't resolving correctly.
//!
//! ## Combining the two
//!
//! Since strictness controls resolution behavior and diagnostics
//! controls reporting across the whole pipeline, they can be mixed
//! freely:
//!
//! - `Normal` + `default()` - good general-purpose defaults.
//! - `Permissive` + `silent()` - maximum tolerance. Tries every
//!   fallback, suppresses all diagnostics, only fails on fatal errors.
//!   Good for loading a pile of vendor MIBs where you want whatever
//!   data you can get. Be aware that some resolved symbols may be
//!   incorrect due to ambiguous fallback matches.
//! - `Strict` + `verbose()` - maximum strictness. No fallbacks, all
//!   diagnostics reported (including parse warnings and style issues).
//!   Good for validating MIBs you author.
//! - `Normal` + `quiet()` - reasonable for a production SNMP tool that
//!   loads user-provided MIBs. Safe fallbacks, but only real errors
//!   are surfaced.
//!
//! ## Fine-tuning
//!
//! For more control, [`DiagnosticConfig`] also supports:
//!
//! - `fail_at` - change which severity causes `load()` to return an
//!   error. For example, set to [`Severity::Minor`] to fail on any
//!   minor issue.
//! - `overrides` - promote or demote specific diagnostic codes (e.g.
//!   turn a warning into an error).
//! - `ignore` - glob patterns to suppress specific diagnostic codes
//!   entirely (e.g. `"import-*"` to ignore all import-related
//!   diagnostics).
//!
//! # Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `serde` | yes | Serde support and JSON export via [`export`] |
//! | `cli` | yes | CLI binary (`mib-rs`) |
//!
//! # Examples
//!
//! Runnable examples live in the `examples/` directory. Each one can be run
//! with `cargo run --example <name>`.
//!
//! ## Basic usage
//!
//! Load a MIB from memory, query objects, and display module metadata.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/basic.rs")]
//! ```
//!
//! ## OID tree walking
//!
//! Root traversal, subtree iteration, depth-first walk, and node navigation.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/walk.rs")]
//! ```
//!
//! ## Type introspection
//!
//! Type chains, effective values, constraints, enums, display hints,
//! and classification predicates.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/types.rs")]
//! ```
//!
//! ## Table navigation
//!
//! Tables, rows, columns, indexes, and object kind predicates.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/tables.rs")]
//! ```
//!
//! ## Module metadata
//!
//! Module metadata, imports, revisions, base modules, and module-scoped
//! iteration.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/modules.rs")]
//! ```
//!
//! ## JSON export
//!
//! JSON export of a resolved MIB using the serde-based export API.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/export.rs")]
//! ```
//!
//! ## Notifications, groups, and compliance
//!
//! Notifications, object groups, notification groups, and compliance statements.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/notifications.rs")]
//! ```
//!
//! ## Query formats
//!
//! Plain names, qualified names, numeric OIDs, instance OIDs, and OID formatting.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/query.rs")]
//! ```
//!
//! ## Diagnostics
//!
//! Diagnostic collection, strictness levels, reporting configuration,
//! filtering, and severity overrides.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/diagnostics.rs")]
//! ```
//!
//! ## Raw data access
//!
//! Low-level raw data access using arena IDs and the RawMib view.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/raw.rs")]
//! ```
//!
//! ## Tokenization
//!
//! Lexical tokenization of MIB source text for syntax highlighting,
//! linting, or custom tooling.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/tokens.rs")]
//! ```
//!
//! ## Sources
//!
//! Source types: in-memory modules, directory sources, chaining,
//! and module listing.
//!
//! ```rust,no_run
#![doc = include_str!("../examples/sources.rs")]
//! ```
pub mod ast;
pub mod error;
#[cfg(feature = "serde")]
pub mod export;
pub(crate) mod graph;
pub mod ir;
pub(crate) mod lexer;
pub mod load;
pub mod lower;
pub mod mib;
pub mod parser;
pub(crate) mod scan;
pub mod searchpath;
pub mod source;
pub mod token;
pub mod types;

// Re-exports for convenience
pub use error::LoadError;
pub use load::{Loader, load};
pub use mib::{
    Capability, Compliance, Group, Index, Mib, Module, Node, Notification, Object, Oid,
    ParseOidError, ResolveOidError, Type,
};
pub use source::{FindResult, Source};
pub use token::{Token, TokenKind};
pub use types::{
    Access, AccessKeyword, BaseType, DiagCode, Diagnostic, DiagnosticConfig, IndexEncoding, Kind,
    Language, ReportingLevel, ResolverStrictness, Severity, Status,
};

/// Low-level resolved data access.
///
/// This module exposes arena ids, backing records, and the explicit
/// [`RawMib`](raw::RawMib) view returned by [`Mib::raw()`].
pub mod raw {
    pub use crate::mib::{
        CapabilityData, CapabilityId, ComplianceData, ComplianceId, GroupData, GroupId, ModuleData,
        ModuleId, NodeData, NodeId, NotificationData, NotificationId, ObjectData, ObjectId,
        OidTree, RawMib, Symbol, TypeData, TypeId,
    };
}

/// Compiler pipeline APIs exposed before final resolution.
///
/// These modules are useful when building syntax-aware tooling or diagnostics
/// that need direct access to tokens, parsed AST, lowered IR, or the parser
/// entry points themselves.
pub mod compile {
    pub use crate::{ast, ir, lower, parser, token};
}
