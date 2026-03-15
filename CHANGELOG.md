# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

- Add 12 runnable examples covering the full public API (basic, walk, types, tables, modules, export, notifications, query, diagnostics, raw, tokens, sources)
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

[Unreleased]: https://github.com/lukeod/mib-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/lukeod/mib-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/lukeod/mib-rs/compare/v0.1.3...v0.2.0
[0.1.3]: https://github.com/lukeod/mib-rs/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lukeod/mib-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lukeod/mib-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lukeod/mib-rs/releases/tag/v0.1.0
