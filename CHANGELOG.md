# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/lukeod/mib-rs/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/lukeod/mib-rs/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/lukeod/mib-rs/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/lukeod/mib-rs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/lukeod/mib-rs/releases/tag/v0.1.0
