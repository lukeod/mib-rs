//! SNMP MIB parsing, resolution, query, and tooling APIs.
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
//! # OID Resolution
//!
//! Resolve symbolic and numeric OIDs, including instance suffixes:
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
//! Navigate tables, columns, and effective indexes through object handles:
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
//! # Module Iteration
//!
//! Scope lookups to a module and iterate the resolved handles it owns:
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
//! [`Mib::resolve_oid`], [`Mib::resolve_node`], and [`Mib::resolve`] accept
//! several query forms:
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
//! Sources provide MIB file content to the loading pipeline. The [`source`]
//! module has several constructors:
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
//! Types form parent chains that terminate at a base SMI type. Each [`Type`]
//! handle exposes both its own properties and effective (inherited) values:
//!
//! | Method | Description |
//! |--------|-------------|
//! | [`Type::base`] | Directly assigned base type |
//! | [`Type::effective_base`] | Base type after following the parent chain |
//! | [`Type::parent`] | Immediate parent type (if derived) |
//! | [`Type::display_hint`] | This type's own DISPLAY-HINT |
//! | [`Type::effective_display_hint`] | First non-empty hint in the chain |
//! | [`Type::enums`] | This type's own enum values |
//! | [`Type::effective_enums`] | First non-empty enums in the chain |
//! | [`Type::sizes`] / [`Type::ranges`] | This type's own constraints |
//! | [`Type::effective_sizes`] / [`Type::effective_ranges`] | Inherited constraints |
//! | [`Type::is_textual_convention`] | Whether defined as a TEXTUAL-CONVENTION |
//!
//! Convenience predicates: [`Type::is_counter`], [`Type::is_gauge`],
//! [`Type::is_string`], [`Type::is_enumeration`], [`Type::is_bits`].
//!
//! Objects expose the same effective accessors directly (e.g.
//! [`Object::effective_display_hint`], [`Object::effective_enums`]) without
//! needing to go through the type handle.
//!
//! # Diagnostics
//!
//! The library collects diagnostics rather than failing fast. After loading,
//! inspect them via [`Mib::diagnostics`] and [`Mib::has_errors`].
//!
//! Two independent controls affect behavior:
//!
//! - **[`ResolverStrictness`]** controls resolver fallback behavior (how
//!   aggressively the resolver attempts to recover from issues). Set via
//!   [`Loader::resolver_strictness`](load::Loader::resolver_strictness).
//! - **[`DiagnosticConfig`]** controls reporting and failure thresholds (which
//!   diagnostics are surfaced, and which severity causes [`LoadError::DiagnosticThreshold`]).
//!   Set via [`Loader::diagnostic_config`](load::Loader::diagnostic_config).
//!
//! [`DiagnosticConfig`] has presets via [`ReportingLevel`]:
//!
//! | Preset | Reports | Fails at |
//! |--------|---------|----------|
//! | `Verbose` | All (including style/info) | Severe |
//! | `Default` | Minor and above | Severe |
//! | `Quiet` | Error and above | Severe |
//! | `Silent` | Nothing | Fatal only |
//!
//! Individual diagnostic codes can be overridden or suppressed via
//! [`DiagnosticConfig::overrides`] and [`DiagnosticConfig::ignore`].
//!
//! # Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `serde` | yes | Serde support and JSON export via [`export`] |
//! | `cli` | yes | CLI binary (`mib-rs`) |
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
