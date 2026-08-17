# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- Replace borrowed index-suffix decoding with an owned `IndexSchema` that provides exact decoding and canonical encoding
- Change `Object::node()` to return `Option<Node>` and retain object metadata when numeric OID resolution fails
- Remove `DiagCode::EmptyRevisionDescription`; empty `REVISION DESCRIPTION` clauses now use `DiagCode::EmptyDescription` (`empty-description`)
- Include all collected diagnostics in deterministic order in `LoadError::DiagnosticThreshold`

### Added

- Preserve precise integer and octet value kinds, normalized effective constraints, component raw arcs, and typed codec failures
- Add object-specific index codec bindings for enforcing the 128-arc complete instance-OID limit
- Report zero-width index components and schemas without rejecting representable definitions
- Report duplicate and unresolved `INCLUDES` groups and `CREATION-REQUIRES` objects in agent capabilities

### Changed

- Classify unresolved and wrong-kind `OBJECT-GROUP` and `NOTIFICATION-GROUP` members as minor diagnostics

### Fixed

- Validate dates, revision ordering, and `LAST-UPDATED` matching for every `MODULE-IDENTITY` regardless of inferred module language
- Distinguish notification `OBJECTS` references to OID nodes without attached object definitions from unknown symbols
- Report missing `INTEGER`, `BITS`, `OCTET STRING`, and `OBJECT IDENTIFIER` types when resolving inline syntax
- Preserve overflowing decimal range endpoints as raw values with `unknown-range-value` diagnostics

## [0.9.0] - 2026-08-13

### Breaking Changes

- Represent resolved range endpoints with `RangeBound` instead of `i64`
- Make `RangeBound` and `Range` clone-only so unresolved endpoints can preserve source text

### Changed

- Link type parents through direct map lookups instead of scanning all parent references for each type
- Document octet-string hexadecimal DISPLAY-HINT output as fixed-width, byte-oriented formatting, including segments above eight bytes
- Preserve signed, unsigned, `MIN`, and `MAX` range endpoints and intersect derived constraints with parent constraints

### Fixed

- Make the `cli` feature enable the Serde dependencies required by CLI JSON output
- Report an OID tree containing only its synthetic root as empty
- Count unqualified imported roots in compound OID DEFVAL values as used imports
- Expand literal `$HOME` occurrences in net-snmp MIB paths from configuration and `MIBDIRS`
- Exclude entities without object types from CLI `find --type` results
- Reject CLI lint severity numbers outside the supported `0..=6` range
- Gate the JSON export example and its embedded documentation on the `serde` feature
- Resolve definition names independently of preferred OID-tree attachments when OIDs are shared
- Detect SMI versions from unambiguous syntax and base module names as well as imports
- Apply diagnostic severity overrides to stored diagnostics and load failure checks
- Keep lexer diagnostics attached to the source module containing their span
- Report configurable, non-fatal diagnostics for INTEGER enumeration values outside Integer32 while preserving their declared values
- Parse whitespace inside hexadecimal range literals consistently with the lexer and preserve malformed endpoints as unresolved source text
- Ignore `END` keywords inside quoted strings when skipping MACRO bodies
- Prevent malformed non-ASCII timestamps from panicking module preference resolution
- Leave generic TRAP-TYPE definitions unresolved when incrementing their number would overflow
- Reject import forwarding chains that do not end at a module defining the symbol
- Leave cyclic type parent references unlinked and report them as dependency cycles
- Resolve compliance and capability export references within their declared module scope
- Skip consecutive EXPORTS clauses without recursive parser calls
- Ignore semicolons inside comments while skipping EXPORTS clauses
- Prevent quoted or malformed phantom module headers from shadowing valid source candidates
- Allow distinct MIB candidates to decode concurrently while initializing each cache entry once

## [0.8.0] - 2026-03-19

### Added

- Add `inspect` CLI subcommand for detailed symbol inspection (type chains, provenance, group membership, diagnostics, column tables)
- Add `imports_symbol()` and `import_source()` methods to Module handle
- Add `index()` iterator to Object handle for raw INDEX entries

### Changed

- Resolve object indexes through global fallback lookup in permissive mode

### Fixed

- Fix `scan_module_names` skipping names when comments precede DEFINITIONS

## [0.7.1] - 2026-03-19

### Changed

- Make `Node::module()` return the selected owner of the OID tree node
- Use the selected module's `OBJECT-TYPE` when classifying nodes that share an OID

## [0.7.0] - 2026-03-18

### Added

- Add `mib::index` module with `decode_suffix()` for decoding OID instance suffixes into typed index values per RFC 2578 section 7.7
- Add `IndexValue` enum (Integer, IpAddress, OctetString, ObjectIdentifier) and `DecodedIndex` type
- Add `OidLookup::decode_indexes()` convenience method
- Re-export `DecodedIndex` and `IndexValue` from crate root

## [0.6.0] - 2026-03-18

### Added

- Add `source::file()` and `source::files()` for loading individual MIB files from disk with automatic module name detection
- Add `OidLookup` type and `Mib::lookup_instance()` for returning both the matched node and instance suffix from a longest-prefix lookup

### Changed

- Refactor `format_oid` to use `lookup_instance` internally

## [0.5.0] - 2026-03-18

### Breaking Changes

- `format_integer()` and `format_octets()` now require a `HexCase` parameter (both standalone functions and `Object` handle methods)

### Added

- Add `HexCase` enum for upper/lower hex output control
- Add `DisplayHint::parse()` for structured hint representation
- Add `parsed_display_hint()` method on `Object` and `Type` handles
- Add display-hint validation helpers (`is_valid_integer_hint`, `is_valid_octet_string_hint`)

### Changed

- Optimize hex formatting with lookup table instead of write!
- Cache parsed hint spec to avoid re-parsing on implicit repetition

## [0.4.0] - 2026-03-18

### Added

- Add RFC 2579 DISPLAY-HINT formatting for integer and octet-string values
- Add `format_integer()`, `scale_integer()`, `format_octets()` methods on `Object` handle
- Add standalone `display_hint::format_integer()`, `display_hint::format_octets()`, `display_hint::scale_integer()` functions

### Changed

- Rewrite crate-level API documentation (simplify tier descriptions, add raw data and compiler pipeline sections)
- Update README feature list with display-hint formatting

## [0.3.0] - 2026-03-15

### Breaking Changes

- Rename `export_v1` to `export_payload`
- Change `description` fields to `Option<String>` in `ExportRevision`, `ExportNotification`, `ExportGroup`, `ExportCompliance`, `ExportCapability`

### Added

- Add CLI parity features across all subcommands
- Expand rustdoc coverage for mid-level MIB concepts
- Expand ResolverStrictness docs with per-level behavior details

### Fixed

- Fix CLI get output and dump export issues

## [0.2.0] - 2026-03-15

### Breaking Changes

- Remove `table_objects()`, `scalar_objects()`, `column_objects()`, `row_objects()` from `Mib` (use `tables()`, `scalars()`, `columns()`, `rows()` instead)
- Move `_slice()` methods, `tree()`, `resolve()`, and `effective_module()` from `Mib` to `RawMib`
- `tables()`, `scalars()`, `columns()`, `rows()` now return handle iterators instead of `Vec<ObjectId>`

### Added

- Add `id()` method to all handle types for handle-to-raw bridge
- Add `HandleIter` impls for Notification, Group, Compliance, Capability
- Add `*_by_id()` bridge methods on `Mib` for all handle types (node, object, type, module, notification, group, compliance, capability)
- Add `user_modules()` filtered iterator on `Mib`
- Add `--version` flag to CLI
- Add `--kind notification` support to CLI find command using ValueEnum

### Changed

- Expand API Tiers section in crate docs with per-tier capabilities and a choosing-a-tier table
- Rewrite raw example to cover sub-clause spans, import metadata, OID references, symbol tables, bulk arena access, OID tree traversal, cross-references, and tier crossing
- Make CLI `--max-depth` imply `--tree`, change to `Option<usize>`
- Print CLI lint diagnostics to stderr
- Return exit code 1 from CLI paths command when no system paths found
- Use `clap::ValueEnum` for CLI `--kind` flag

### Fixed

- Fix private-item doc link warnings for `Mib::resolve`
- Fix CLI kind filter rejecting valid values

### Dependencies

- Bump clap 4.5.60 -> 4.6.0
- Bump anstream 0.6.21 -> 1.0.0
- Bump tracing-subscriber 0.3.22 -> 0.3.23
- Bump libc, once_cell, anstyle, colorchoice and other transitive deps

## [0.1.3] - 2026-03-14

### Added

- Add 12 runnable examples for loading, queries, OID walks, types, tables, modules, export, notifications, diagnostics, raw data, tokens, and sources
- Embed examples in crate-level rustdoc via include_str

### Changed

- Expand crate docs with MIB/SNMP background for non-experts
- Add guidance on effective_* vs direct type accessors
- Document ResolverStrictness and DiagnosticConfig tradeoffs with practical recommendations
- Explain correctness vs completeness tradeoff for resolver fallback levels

## [0.1.2] - 2026-03-13

### Changed

- Expand rustdoc coverage across all public types and modules
- Add lib.rs sections for query formats, sources, type introspection, diagnostics, and feature flags
- Add field-level doc comments to export, IR, and mib/types structs

## [0.1.1] - 2026-03-13

### Fixed

- Improved rustdoc coverage and accuracy across all modules
- Fixed broken rustdoc links in error and source modules

## [0.1.0] - 2026-03-13

### Added

- SMIv1 (RFC 1155/1212/1215) and SMIv2 (RFC 2578/2579/2580) parser
- Five-phase resolver: registration, imports, types, OIDs, semantics
- OID tree with numeric and symbolic resolution, instance lookups
- Type chains with effective base type, display hints, enums, bit fields, ranges
- Table, row, column, and index resolution (including AUGMENTS and IMPLIED)
- Notification, group, compliance, and capability resolution
- Diagnostic collection with configurable strictness (permissive, normal, strict)
- Synthetic base modules: SNMPv2-SMI, SNMPv2-TC, SNMPv2-CONF, RFC1155-SMI, RFC1065-SMI, RFC-1212, RFC-1215
- System MIB path discovery for net-snmp and libsmi installations
- Parallel file loading with rayon
- Three API tiers: high-level handles, low-level raw arena data, compiler pipeline
- Memory source for loading MIBs from strings/bytes
- Directory and directory-tree source implementations
- JSON export (schema v1) with serde feature
- CLI tool with load, get, find, list, lint, paths, and dump commands
- Tracing integration for debug and trace logging

[Unreleased]: https://github.com/lukeod/mib-rs/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/lukeod/mib-rs/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/lukeod/mib-rs/compare/v0.7.1...v0.8.0
[0.7.1]: https://github.com/lukeod/mib-rs/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/lukeod/mib-rs/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/lukeod/mib-rs/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/lukeod/mib-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/lukeod/mib-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/lukeod/mib-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lukeod/mib-rs/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/lukeod/mib-rs/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lukeod/mib-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lukeod/mib-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lukeod/mib-rs/releases/tag/v0.1.0
