//! Shared types used across the MIB parsing pipeline.
//!
//! Contains enums for SMI concepts ([`Access`], [`Status`], [`Kind`], [`BaseType`]),
//! diagnostic infrastructure ([`Diagnostic`], [`DiagCode`], [`DiagnosticConfig`]),
//! source spans ([`Span`], [`ByteOffset`]), line table utilities
//! ([`build_line_table`], [`line_col_from_table`]), configuration types
//! ([`ResolverStrictness`], [`ReportingLevel`]), and reference tables for SMI
//! [`macro`](macro_info) and [`clause`](clause_info) keywords.

pub mod clause_info;
mod diagcode;
mod diagnostic;
mod enums;
mod line_table;
pub mod macro_info;
mod span;

pub use diagcode::{DiagCode, all_diagnostic_codes};
pub use diagnostic::{Diagnostic, DiagnosticConfig};
pub use enums::{
    Access, AccessKeyword, BaseType, IndexEncoding, Kind, Language, ReportingLevel,
    ResolverStrictness, Severity, Status,
};
pub use line_table::{build_line_table, line_col_from_table};
pub use span::{ByteOffset, Span, SpanDiagnostic};
