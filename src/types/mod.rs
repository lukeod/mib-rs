//! Shared types used across the MIB parsing pipeline.
//!
//! Contains enums for SMI concepts ([`Access`], [`Status`], [`Kind`], [`BaseType`]),
//! diagnostic infrastructure ([`Diagnostic`], [`DiagCode`], [`DiagnosticConfig`]),
//! checked diagnostics, configuration types ([`ResolverStrictness`],
//! [`ReportingLevel`]), and reference tables for SMI
//! [`macro`](macro_info) and [`clause`](clause_info) keywords.

pub mod clause_info;
mod diagcode;
mod diagnostic;
mod enums;
pub mod macro_info;

pub use diagcode::{DiagCode, all_diagnostic_codes};
pub use diagnostic::{Diagnostic, DiagnosticConfig, SpanDiagnostic};
pub use enums::{
    Access, AccessKeyword, BaseType, IndexEncoding, Kind, Language, ReportingLevel,
    ResolverStrictness, Severity, Status,
};
