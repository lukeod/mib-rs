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
//! Information), which has two versions: SMIv1 (RFC 1155/1212/1215) and
//! SMIv2 (RFC 2578/2579/2580). This crate parses both versions.
//!
//! # API Layers
//!
//! Most callers should use the **handle API**: start with [`Loader`],
//! get a [`Mib`], and navigate the resolved model through borrowed
//! handle types ([`Node`], [`Object`], [`Type`], [`Module`],
//! [`Notification`], [`Group`], [`Compliance`], [`Capability`]).
//! Handles wrap an arena ID and a `&Mib` reference. Methods on
//! handles return further handles, so typical usage looks like
//! `object.ty()?.effective_base()` without touching IDs directly.
//! The handle API covers OID resolution, type-chain introspection,
//! table and index navigation, module iteration, and diagnostics.
//!
//! Every handle exposes its arena ID via `.id()`. IDs are
//! `Copy + Eq + Hash + Ord`, so you can store them in collections
//! for deduplication or cross-referencing, then convert back to
//! handles with `mib.*_by_id()` when you need to query again.
//!
//! [`Mib`] also has query methods that work with IDs directly:
//! [`Mib::modules_defining`] and [`Mib::modules_importing`] find
//! modules by symbol name, [`Mib::objects_by_base_type`] and
//! [`Mib::objects_by_type_name`] filter objects by type, and
//! [`Mib::available_symbols`] returns everything visible in a
//! module's scope (own definitions plus resolved imports).
//!
//! ## Raw data access
//!
//! [`Mib::raw()`] returns a [`RawMib`](raw::RawMib) view that
//! exposes the arena-backed data records directly. This is useful
//! when you need things the handle API doesn't surface:
//!
//! - Per-clause source ranges on [`ObjectData`](raw::ObjectData)
//!   and [`TypeData`](raw::TypeData) (e.g. `syntax_range`,
//!   `access_range`) for pointing diagnostics at specific clauses.
//! - Import metadata ([`ModuleData::is_import_used`](raw::ModuleData::is_import_used),
//!   [`ModuleData::import_source`](raw::ModuleData::import_source)).
//! - Symbolic OID references via `oid_refs()` on entity records.
//! - Bulk arena slices (`raw.*_slice()`) for batch analysis.
//!
//! See the [`raw`] module and the `raw` example.
//!
//! ## Compiler pipeline
//!
//! The [`ast`], [`parser`], [`lower`], [`ir`], and [`token`]
//! modules expose pre-resolution stages for callers that need
//! syntax-aware analysis before full resolution. The parser
//! produces partial ASTs from broken input, which matters for
//! editor integration where the user is mid-edit. [`SyntaxKind`] is the single
//! token/node inventory and carries fixed spellings, keyword aliases, and
//! classification predicates for syntax highlighting and parser dispatch.
//! See the [`compile`] module and the `tokens` example.
//!
//! [`SourceDocument`] and [`SourceSet`] provide immutable source storage for
//! parse-only and tooling consumers. Checked [`ByteOffset`] and [`SourceRange`]
//! values identify byte coordinates without sentinel values. [`BytePosition`]
//! round-trips arbitrary source bytes, while [`Position`] requires an explicit
//! [`PositionEncoding`] for UTF-8, UTF-16, or UTF-32 editor coordinates.
//! [`Diagnostic`] retains an optional full source range, and
//! [`DiagnosticReport`] keeps the referenced documents alive while deriving
//! report-owned [`DiagnosticEntry`] handles. Entry rendering includes the
//! source label plus the full start and exclusive end; invalid or unretained
//! ranges return [`DiagnosticReportError`] instead of fabricated coordinates.
//! Reports are obtained from a resolved [`Mib`] or a threshold [`LoadError`]
//! and share that compilation's exact source arena; callers cannot combine
//! diagnostics with an unrelated [`SourceSet`] or resolve raw diagnostic
//! metadata through a different report.
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
//!     REVISION "202603120000Z"
//!     DESCRIPTION "Initial version."
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
//! Objects, notifications, and other OID-bearing definitions occupy a path
//! in the global OID tree. OIDs are written as dotted decimal
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
//! The column `ifDescr` for interface 7 has OID `ifDescr.7` (i.e.
//! the column's base OID with the index value `7` appended).
//!
//! ## AUGMENTS
//!
//! Some rows use `AUGMENTS` instead of `INDEX`. An augmenting row
//! extends another table's rows with additional columns, sharing the
//! same index structure. For example, `ifXEntry AUGMENTS ifEntry`
//! adds columns like `ifHighSpeed` to each `ifEntry` row, using the
//! same `ifIndex` to identify rows. Use [`Object::augments`] to find
//! the target row and [`Object::augmented_by`] to find extending rows.
//! [`Object::effective_indexes`] follows the augment chain
//! automatically, returning the inherited index list.
//!
//! ## Index encoding
//!
//! Each index component has an [`IndexEncoding`] that describes how
//! its value maps to OID sub-identifiers in the instance suffix.
//! Integer indexes use a single sub-identifier. Fixed-length strings
//! (with a single-value SIZE constraint) use one sub-identifier per
//! octet. Variable-length strings are length-prefixed. The `IMPLIED`
//! keyword omits the length prefix, relying on the index being the
//! last component. [`Index::encoding`] returns the derived encoding.
//!
//! Compile an owned [`IndexSchema`] from a row or column, then use
//! [`IndexSchema::decode_exact`] and [`IndexSchema::encode_canonical`] after
//! the MIB is dropped. Exact decoding rejects truncated, malformed, and
//! trailing input; canonical encoding validates value kinds and constraints.
//! Inspect [`IndexSchema::issues`] and [`IndexComponentSchema::issues`] for
//! representable MIB concerns retained during compilation.
//!
//! Use [`Object::is_table`], [`Object::is_row`], [`Object::is_column`],
//! and [`Object::is_scalar`] to distinguish these, or use the filtered
//! iterators like [`Mib::tables`] and [`Mib::scalars`].
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
//! A MIB module is a named definition unit such as `IF-MIB` or
//! `SNMPv2-MIB`. A source file usually contains one module, although the
//! parser also accepts concatenated modules. Modules import symbols from
//! other modules, so the loader also loads requested modules' dependencies.
//!
//! ## Base modules
//!
//! Seven **base modules** are built into the library and always available:
//!
//! | Module | SMI version | Defines |
//! |--------|-------------|---------|
//! | `SNMPv2-SMI` | SMIv2 | Core types (`Integer32`, `Counter32`, etc.), OID roots (`internet`, `enterprises`, `mib-2`), macros (`MODULE-IDENTITY`, `OBJECT-TYPE`, `NOTIFICATION-TYPE`, `OBJECT-IDENTITY`) |
//! | `SNMPv2-TC` | SMIv2 | `TEXTUAL-CONVENTION` macro, standard TCs (`DisplayString`, `TruthValue`, `RowStatus`, etc.) |
//! | `SNMPv2-CONF` | SMIv2 | Conformance macros (`MODULE-COMPLIANCE`, `OBJECT-GROUP`, `NOTIFICATION-GROUP`, `AGENT-CAPABILITIES`) |
//! | `RFC1155-SMI` | SMIv1 | SMIv1 base types and OID roots |
//! | `RFC1065-SMI` | SMIv1 | Earlier SMIv1 base (predecessor to RFC1155-SMI) |
//! | `RFC-1212` | SMIv1 | SMIv1 `OBJECT-TYPE` macro definition |
//! | `RFC-1215` | SMIv1 | SMIv1 `TRAP-TYPE` macro definition |
//!
//! These modules define the SMI language itself, including the ASN.1 macros
//! (`OBJECT-TYPE`, `MODULE-IDENTITY`, `TEXTUAL-CONVENTION`, etc.) that other
//! MIB modules use. RFC-derived module sources are embedded as fallbacks and
//! parsed through the normal pipeline. They are byte-synchronized with gomib
//! and include deliberate adaptations rather than being literal RFC text;
//! macro bodies are recognized and skipped because MIB definitions use the
//! fixed standard macro set.
//!
//! Implications for users:
//!
//! - **No files needed:** You do not need to supply these modules as source
//!   files. A copy in a configured source takes precedence over the embedded
//!   fallback and is parsed normally.
//! - **Always present:** Base modules are included in every loaded [`Mib`],
//!   even if nothing imports them. Use [`Module::is_base`] to distinguish
//!   them from user-supplied modules (e.g. when iterating modules).
//! - **Source locations:** Parsed definitions have source-qualified ranges. Embedded
//!   modules use source labels such as `embedded:SNMPv2-SMI`; configured copies
//!   retain the label reported by their source.
//! - **Included in iteration:** [`Mib::modules`], [`Mib::objects`],
//!   [`Mib::types`], and [`Mib::nodes`] all include base module content.
//!   Filter with [`Module::is_base`] when you only want user-supplied
//!   definitions. Module-scoped iterators (e.g. `module.objects()`) are
//!   naturally limited to a single module.
//!
//! ## OID ownership
//!
//! Several base modules define overlapping OID trees. For example, both
//! `RFC1155-SMI` (SMIv1) and `SNMPv2-SMI` (SMIv2) define `internet`,
//! `enterprises`, and other well-known roots. When multiple modules
//! register the same OID, the resolver determines which module "owns"
//! the node using these tiebreakers, in order:
//!
//! - Base modules take priority over user modules.
//! - SMIv2 modules are preferred over SMIv1.
//! - Among modules with the same SMI version, newer `LAST-UPDATED`
//!   timestamps win.
//! - Lexicographic module name as a final deterministic fallback.
//!
//! In practice this means `SNMPv2-SMI` owns nodes like `enterprises`
//! even though `RFC1155-SMI` also defines them. [`Node::module`] returns
//! the winning module. Both modules still function normally for imports,
//! so SMIv1 MIBs that `IMPORTS ... FROM RFC1155-SMI` continue to work.
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
//! # Notifications and Conformance
//!
//! Beyond objects and types, SMI defines several constructs for
//! event reporting and conformance testing:
//!
//! - **NOTIFICATION-TYPE** (SMIv2) / **TRAP-TYPE** (SMIv1) - defines
//!   an asynchronous event an agent can send. Each notification lists
//!   the objects it carries as payload via its OBJECTS clause. SMIv1
//!   traps additionally carry an enterprise OID and trap number.
//!   See [`Notification`] and [`Notification::objects`].
//!
//! - **OBJECT-GROUP** / **NOTIFICATION-GROUP** - bundles related
//!   objects or notifications into a named set. Groups are the unit
//!   of conformance: a compliance statement says "you must implement
//!   these groups". See [`Group`] and [`Group::members`].
//!
//! - **MODULE-COMPLIANCE** - declares which groups a compliant
//!   implementation must support, with optional per-object refinements
//!   that can narrow syntax or access requirements. See [`Compliance`].
//!
//! - **AGENT-CAPABILITIES** - declares what an actual agent
//!   implementation supports, including which groups it includes and
//!   any per-object variations (restricted syntax, different defaults).
//!   See [`Capability`].
//!
//! These are less commonly needed than objects and types, but matter
//! for MIB validation tooling, compliance checking, and understanding
//! which objects are required vs optional. The `notifications` example
//! demonstrates querying all four.
//!
//! # Query Formats
//!
//! Once a MIB is loaded, you can look up nodes and OIDs using several
//! formats. Qualified names (`MODULE::name`) are useful when multiple
//! modules define the same name. [`Mib::resolve_oid`],
//! [`Mib::resolve_node`], and [`RawMib::resolve`](raw::RawMib::resolve) all accept these forms:
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
//! | [`source::file()`] | Single file on disk, module name auto-detected |
//! | [`source::files()`] | Multiple files on disk, module names auto-detected |
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
//! A **textual convention** (TC) is the standard way to define reusable
//! types in SMIv2 (RFC 2579). A TC wraps a base type with a name,
//! description, and optional DISPLAY-HINT and constraints. For example,
//! `DisplayString` is a TC over `OCTET STRING (SIZE (0..255))` with
//! display hint `"255a"`. Use [`Type::is_textual_convention`] to check
//! whether a type was defined as a TC.
//!
//! ## Constraints: SIZE vs range
//!
//! Both [`Type::sizes`] and [`Type::ranges`] return `&[Range]`, but
//! they constrain different things:
//!
//! - **SIZE** constrains the length (in octets) of string-like types
//!   (`OCTET STRING`, `Opaque`). Example: `SIZE (0..255)` means
//!   at most 255 bytes.
//! - **Range** constrains the numeric value of integer-like types.
//!   Example: `(1..2147483647)` means the value must be at least 1.
//!
//! The `effective_*` variants intersect constraints declared across the
//! parent chain. An empty effective slice can mean either no constraint or an
//! unsatisfiable intersection; the corresponding `*_constrained` accessor
//! distinguishes those cases.
//!
//! ## Display hints
//!
//! A DISPLAY-HINT string (RFC 2579, Section 3) tells a MIB browser or
//! SNMP tool how to render a raw value as human-readable text. Common
//! examples:
//!
//! - `"255a"` - up to 255 ASCII characters (used by `DisplayString`)
//! - `"1x:"` - hex bytes separated by colons (used by `MacAddress`)
//! - `"2d-1d-1d,1d:1d:1d.1d"` - date-time components (used by
//!   `DateAndTime`)
//!
//! [`Type::effective_display_hint`] and
//! [`Object::effective_display_hint`] return the hint string.
//! [`Object::format_integer`], [`Object::format_octets`], and
//! [`Object::scale_integer`] apply the hint directly to raw values.
//! The [`display_hint`](mib::display_hint) module exposes the same
//! formatting functions for use without an Object handle.
//!
//! ## Direct vs effective accessors
//!
//! Each [`Type`] handle exposes two families of accessors:
//!
//! - **Direct** (`base`, `display_hint`, `enums`, `sizes`, `ranges`) -
//!   return only what this specific type declares. These are empty/None
//!   if the type inherits everything from its parent.
//! - **Effective** (`effective_base`, `effective_display_hint`,
//!   `effective_enums`, `effective_sizes`, `effective_ranges`) - return the
//!   resolved answer. SIZE and range constraints are intersected across the
//!   parent chain; other values use the first non-empty value.
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
//! | [`Type::effective_sizes`] / [`Type::effective_ranges`] | Constraints intersected across the parent chain |
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
//! Two settings affect loading:
//!
//! - [`ResolverStrictness`] controls which fallback lookups the resolver may
//!   use for missing or incorrect imports.
//! - [`DiagnosticConfig`] controls which lexer, parser, and resolver
//!   diagnostics are retained and which severities make `load()` fail. It
//!   does not change resolution behavior.
//!
//! Broader fallback lookup can resolve more vendor MIBs, but a global lookup
//! can be ambiguous when several modules define the same name. `Strict`
//! limits resolution to deterministic sources such as explicit imports,
//! import-forwarding chains, and ASN.1 primitives.
//!
//! ## ResolverStrictness - what the resolver attempts
//!
//! [`ResolverStrictness`] controls how aggressively the resolver tries
//! to recover when it can't find a symbol through explicit imports. Set
//! via [`Loader::resolver_strictness`](load::Loader::resolver_strictness).
//!
//! | Level | Behavior | Correctness risk | When to use |
//! |-------|----------|-----------------|-------------|
//! | `Strict` | Uses deterministic resolution paths only. | Lowest | MIB validation, linting, and CI checks. |
//! | `Normal` (default) | Also searches well-known base modules and resolves module-name aliases. | Low | General use and common missing base-module imports. |
//! | `Permissive` | Also permits global fallback for the object and conformance references listed below. | Higher | Vendor MIBs that require global fallback resolution. |
//!
//! ### Specific behaviors by level
//!
//! **All levels (including Strict):**
//! - Direct import resolution (symbol found in the named source module).
//! - Import forwarding: MIB authors often import a symbol from a
//!   module that uses it, not realizing that module doesn't define
//!   the symbol - it imports it from somewhere else. SMI imports
//!   are not transitive (importing from a module only gives you
//!   what that module defines, not what it imports), but many MIB
//!   authors treat them as if they were, similar to how programmers
//!   sometimes confuse which scope a variable is visible in.
//!
//!   For example, suppose `ACME-TC` defines a textual convention
//!   `AcmeStatus`, and `ACME-MIB` imports and uses it:
//!
//!   ```text
//!   ACME-TC DEFINITIONS ::= BEGIN
//!     AcmeStatus ::= TEXTUAL-CONVENTION ...
//!   END
//!
//!   ACME-MIB DEFINITIONS ::= BEGIN
//!     IMPORTS AcmeStatus FROM ACME-TC;
//!     -- uses AcmeStatus in OBJECT-TYPE definitions
//!   END
//!   ```
//!
//!   A third module might then mistakenly import `AcmeStatus` from
//!   `ACME-MIB` instead of from `ACME-TC`:
//!
//!   ```text
//!   ACME-EXTENSION-MIB DEFINITIONS ::= BEGIN
//!     IMPORTS AcmeStatus FROM ACME-MIB;  -- wrong: ACME-MIB doesn't define it
//!   END
//!   ```
//!
//!   The resolver handles this by checking `ACME-MIB`'s own IMPORTS,
//!   finding that it declares `AcmeStatus FROM ACME-TC`, and
//!   following that chain. This is deterministic - the intermediate
//!   module explicitly names its source - so it is enabled at all
//!   strictness levels.
//! - Partial import resolution: when a source module has some but not
//!   all of the requested symbols, the ones that exist are resolved
//!   individually and the rest are reported as unresolved.
//! - ASN.1 primitive type fallback: `INTEGER`, `OCTET STRING`,
//!   `OBJECT IDENTIFIER`, and `BITS` always resolve from SNMPv2-SMI
//!   even without an explicit import.
//! - Well-known OID roots: `iso`, `ccitt`, and `joint-iso-ccitt`
//!   always resolve to their fixed arc values.
//!
//! **Normal and Permissive (constrained fallbacks):**
//! - Module name aliases: maps alternate module names to their
//!   canonical form (e.g. `SNMPv2-SMI-v1` to `SNMPv2-SMI`,
//!   `RFC-1213` to `RFC1213-MIB`). These aliases exist because
//!   modules have been renamed over time as RFCs were revised,
//!   and some vendors use non-standard names in their IMPORTS.
//! - Unimported well-known symbol fallback: names like `enterprises`,
//!   `Counter64`, and `DisplayString` feel like built-in language
//!   keywords, but they're actually defined in specific base modules
//!   (`SNMPv2-SMI`, `SNMPv2-TC`, etc.) and formally need to be
//!   imported. Many MIB authors skip the import, treating these names
//!   as globally available:
//!
//!   ```text
//!   ACME-MIB DEFINITIONS ::= BEGIN
//!     IMPORTS
//!       MODULE-IDENTITY, OBJECT-TYPE
//!         FROM SNMPv2-SMI;
//!     -- no import for enterprises or Counter64
//!
//!     acmeMib MODULE-IDENTITY ... ::= { enterprises 12345 }
//!
//!     acmeCounter OBJECT-TYPE
//!       SYNTAX Counter64   -- not imported
//!       ...
//!   END
//!   ```
//!
//!   When a type or OID parent is not found via imports, the resolver
//!   searches the well-known base modules (SNMPv2-SMI, RFC1155-SMI,
//!   SNMPv2-TC). This is limited to those specific modules, so there
//!   is no ambiguity about which definition is meant.
//! - TRAP-TYPE enterprise global lookup: the ENTERPRISE reference in
//!   TRAP-TYPE definitions is searched across all modules when not
//!   found via imports.
//!
//! **Permissive only (global fallbacks):**
//! - Global object lookup: INDEX objects, AUGMENTS targets,
//!   NOTIFICATION-TYPE OBJECTS members, and DEFVAL object references
//!   are searched across all loaded modules when not found via imports.
//! - Global group/compliance member lookup: OBJECT-GROUP members,
//!   MODULE-COMPLIANCE mandatory groups, and AGENT-CAPABILITIES
//!   variation targets are searched globally.
//!
//! `Normal` is the default. Use `Strict` when unresolved imports must remain
//! visible, such as during validation or CI. Use `Permissive` when required
//! MIB inputs cannot be corrected and depend on global fallback lookup.
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
//! The default retains minor and more severe diagnostics. `verbose()` also
//! retains informational and style diagnostics; `quiet()` retains errors and
//! more severe diagnostics; `silent()` retains only fatal diagnostics.
//!
//! ## Combining the two
//!
//! Strictness and reporting can be configured independently. For example,
//! `Strict` with `verbose()` retains detailed diagnostics without enabling
//! fallback resolution, while `Permissive` with `quiet()` enables all
//! fallbacks but retains only errors and more severe diagnostics.
//!
//! ## Fine-tuning
//!
//! For more control, [`DiagnosticConfig`] also supports:
//!
//! - `fail_at` - change which severity causes `load()` to return an
//!   error. For example, set to [`Severity::Minor`] to fail on any
//!   minor issue. [`LoadError::DiagnosticThreshold`] owns a [`DiagnosticReport`]
//!   containing every collected diagnostic in deterministic order and retaining
//!   the source documents needed to render locations after the load fails.
//! - `overrides` - promote or demote specific diagnostic codes (e.g.
//!   turn a warning into an error). The effective severity is stored on
//!   collected diagnostics and controls `fail_at`; demotion does not suppress
//!   an otherwise collected diagnostic.
//! - `ignore` - glob patterns to suppress specific diagnostic codes
//!   entirely (e.g. `"import-*"` to ignore all import-related
//!   diagnostics).
//!
//! # Feature Flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `serde` | yes | Serde support and JSON export via `export` |
//! | `cli` | yes | CLI binary (`mib-rs`); enables `serde` |
//!
//! # Examples
//!
//! The repository's [`examples` directory](https://github.com/lukeod/mib-rs/tree/main/examples)
//! contains runnable programs for loading, queries, OID walks, tables, types,
//! notifications, diagnostics, source configuration, raw data, tokenization,
//! and JSON export.
//!
//! Run an example by name:
//!
//! ```text
//! cargo run --example basic
//! cargo run --example tables
//! cargo run --example diagnostics
//! ```
//!
//! The JSON export example requires the `serde` feature.
pub mod ast;
pub mod cst;
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
pub mod syntax;
pub mod token;
pub mod types;

// Re-exports for convenience
pub use error::LoadError;
pub use load::{Loader, load};
pub use mib::{
    Capability, Compliance, Group, Index, Mib, Module, Node, Notification, Object, Oid, OidLookup,
    ParseOidError, ResolveOidError, Type,
    index::{
        BoundIndexCodec, ConstraintCheck, ConstraintMode, DecodeOptions, DecodedIndexComponent,
        DecodedRowIndex, EncodeOptions, InclusiveRange, IncompleteConstraintMode, IndexBindError,
        IndexComponentSchema, IndexConstraintViolation, IndexDecodeError, IndexDecodeErrorKind,
        IndexEncodeError, IndexEncodeErrorKind, IndexSchema, IndexSchemaError, IndexSchemaIssue,
        IndexSuffix, IndexValue, IndexValueKind, IndexValueRef, IndexWireType, IntegerConstraint,
        IntegerIndexKind, LengthConstraint, MAX_INSTANCE_OID_ARCS, NormalizedConstraint,
        OctetIndexKind, PartialRange, ReportedIndexViolation, VariableFraming,
    },
};
pub use source::{
    ByteOffset, BytePosition, CandidateId, Position, PositionEncoding, PositionError, Source,
    SourceCandidate, SourceDocument, SourceId, SourceOrigin, SourceRange, SourceRangeError,
    SourceSet,
};
pub use syntax::{
    FORBIDDEN_KEYWORDS, KeywordCategory, SyntaxCategory, SyntaxKind, is_forbidden_keyword,
    lookup_keyword,
};
pub use token::Token;
pub use types::{
    Access, AccessKeyword, BaseType, DiagCode, Diagnostic, DiagnosticConfig, DiagnosticEntry,
    DiagnosticReport, DiagnosticReportError, IndexEncoding, Kind, Language, ReportingLevel,
    ResolverStrictness, Severity, Status,
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
    pub use crate::{ast, cst, ir, lower, parser, syntax, token};
}
