//! Canonical SMIv2 output for resolved MIB modules.
//!
//! The writer emits one selected module from a resolved [`Mib`] to an
//! arbitrary [`std::io::Write`] destination. Output ordering, imports, and
//! indentation are deterministic.
//!
//! This is currently a partial canonical subset: it emits module identities,
//! object identities, and plain object identifier assignments. Types,
//! `OBJECT-TYPE` definitions, notifications, conformance definitions, and
//! reconstructed sequences are not emitted yet. A successful write therefore
//! does not necessarily contain every declaration from the selected module.
//!
//! Writes are streaming and non-atomic. If the destination returns an I/O
//! error, it may already contain a prefix of the module.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use crate::{Mib, Module, ModuleIdentityData, ModuleIdentityKind, Oid, Status};

const INDENT: &[u8] = b"    ";

/// Options controlling canonical module output.
///
/// All output families are enabled by default. Options whose corresponding
/// definitions are not emitted yet are retained by the writer so future
/// definition emitters can share the same stable configuration API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    descriptions: bool,
    conformance: bool,
    reconstructed_sequences: bool,
}

impl Options {
    /// Create options with descriptions, conformance definitions, and
    /// reconstructed sequences enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            descriptions: true,
            conformance: true,
            reconstructed_sequences: true,
        }
    }

    /// Control whether `DESCRIPTION` clauses are emitted.
    #[must_use]
    pub const fn with_descriptions(mut self, enabled: bool) -> Self {
        self.descriptions = enabled;
        self
    }

    /// Control whether conformance definitions are emitted.
    #[must_use]
    pub const fn with_conformance(mut self, enabled: bool) -> Self {
        self.conformance = enabled;
        self
    }

    /// Control whether reconstructed `SEQUENCE` types are emitted.
    #[must_use]
    pub const fn with_reconstructed_sequences(mut self, enabled: bool) -> Self {
        self.reconstructed_sequences = enabled;
        self
    }

    /// Return whether `DESCRIPTION` clauses are enabled.
    #[must_use]
    pub const fn descriptions(self) -> bool {
        self.descriptions
    }

    /// Return whether conformance definitions are enabled.
    #[must_use]
    pub const fn conformance(self) -> bool {
        self.conformance
    }

    /// Return whether reconstructed `SEQUENCE` types are enabled.
    #[must_use]
    pub const fn reconstructed_sequences(self) -> bool {
        self.reconstructed_sequences
    }
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

/// Error returned while writing a canonical MIB module.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The requested module is not present in the resolved MIB.
    #[error("module not found: {0}")]
    ModuleNotFound(String),
    /// The output destination rejected a write.
    #[error("failed to write canonical MIB: {0}")]
    Io(#[from] io::Error),
}

/// Write one resolved module using default [`Options`].
///
/// # Errors
///
/// Returns [`Error::ModuleNotFound`] when `module_name` is not loaded and
/// [`Error::Io`] when the destination rejects a write. Missing modules are
/// detected before writing; an I/O error may leave a partial module in the
/// destination.
pub fn write<W: Write>(destination: W, mib: &Mib, module_name: &str) -> Result<(), Error> {
    write_with_options(destination, mib, module_name, Options::default())
}

/// Write one resolved module using explicit [`Options`].
///
/// # Errors
///
/// Returns [`Error::ModuleNotFound`] when `module_name` is not loaded and
/// [`Error::Io`] when the destination rejects a write. Missing modules are
/// detected before writing; an I/O error may leave a partial module in the
/// destination.
pub fn write_with_options<W: Write>(
    destination: W,
    mib: &Mib,
    module_name: &str,
    options: Options,
) -> Result<(), Error> {
    let module = mib
        .module(module_name)
        .ok_or_else(|| Error::ModuleNotFound(module_name.to_owned()))?;
    Emitter::new(destination, options).emit_module(module)?;
    Ok(())
}

struct Definitions<'a> {
    module_identities: Vec<&'a ModuleIdentityData>,
    oid_assignments: Vec<&'a ModuleIdentityData>,
    identity_by_oid: BTreeMap<Oid, &'a ModuleIdentityData>,
}

impl<'a> Definitions<'a> {
    fn collect(module: Module<'a>) -> Self {
        let mut module_identities = Vec::new();
        let mut oid_assignments = Vec::new();

        for identity in module.identities() {
            match identity.kind() {
                ModuleIdentityKind::ModuleIdentity => module_identities.push(identity),
                ModuleIdentityKind::ObjectIdentity | ModuleIdentityKind::ObjectIdentifier => {
                    oid_assignments.push(identity);
                }
            }
        }

        module_identities.sort_by_key(|identity| identity.name());
        oid_assignments.sort_by(|left, right| {
            left.oid()
                .cmp(right.oid())
                .then_with(|| left.name().cmp(right.name()))
        });

        let mut identity_by_oid = BTreeMap::new();
        for identity in module_identities.iter().chain(&oid_assignments).copied() {
            identity_by_oid
                .entry(identity.oid().clone())
                .and_modify(|current: &mut &'a ModuleIdentityData| {
                    if identity.name() < current.name() {
                        *current = identity;
                    }
                })
                .or_insert(identity);
        }

        Self {
            module_identities,
            oid_assignments,
            identity_by_oid,
        }
    }

    fn identity_at(&self, oid: &Oid) -> Option<&'a ModuleIdentityData> {
        self.identity_by_oid.get(oid).copied()
    }
}

#[derive(Default)]
struct Imports {
    module_name: String,
    by_module: BTreeMap<String, BTreeSet<String>>,
}

impl Imports {
    fn new(module_name: &str) -> Self {
        Self {
            module_name: module_name.to_owned(),
            by_module: BTreeMap::new(),
        }
    }

    fn add(&mut self, module: &str, symbol: &str) {
        if module.is_empty() || module == self.module_name || symbol.is_empty() {
            return;
        }
        self.by_module
            .entry(module.to_owned())
            .or_default()
            .insert(symbol.to_owned());
    }

    fn add_macro(&mut self, name: &str) {
        let module = match name {
            "MODULE-IDENTITY" | "OBJECT-IDENTITY" => "SNMPv2-SMI",
            _ => return,
        };
        self.add(module, name);
    }

    fn collect(module: Module<'_>, definitions: &Definitions<'_>) -> Self {
        let mut imports = Self::new(module.name());
        for identity in &definitions.module_identities {
            imports.add_macro("MODULE-IDENTITY");
            if let AssignmentParent::External { module, name } =
                assignment_parent(module, definitions, identity)
            {
                imports.add(module, name);
            }
        }
        for identity in &definitions.oid_assignments {
            if identity.kind() == ModuleIdentityKind::ObjectIdentity {
                imports.add_macro("OBJECT-IDENTITY");
            }
            if let AssignmentParent::External { module, name } =
                assignment_parent(module, definitions, identity)
            {
                imports.add(module, name);
            }
        }
        imports
    }
}

struct Emitter<W> {
    destination: W,
    options: Options,
}

impl<W: Write> Emitter<W> {
    fn new(destination: W, options: Options) -> Self {
        Self {
            destination,
            options,
        }
    }

    fn emit_module(&mut self, module: Module<'_>) -> io::Result<()> {
        let definitions = Definitions::collect(module);
        let imports = Imports::collect(module, &definitions);

        self.line(0, format_args!("{} DEFINITIONS ::= BEGIN", module.name()))?;
        self.emit_imports(&imports)?;

        for identity in &definitions.module_identities {
            self.blank_line()?;
            self.emit_module_identity(module, &definitions, identity)?;
        }

        for identity in &definitions.oid_assignments {
            self.blank_line()?;
            match identity.kind() {
                ModuleIdentityKind::ObjectIdentity => {
                    self.emit_object_identity(module, &definitions, identity)?;
                }
                ModuleIdentityKind::ObjectIdentifier => {
                    self.emit_oid_assignment(module, &definitions, identity)?;
                }
                ModuleIdentityKind::ModuleIdentity => {}
            }
        }

        self.blank_line()?;
        self.line(0, format_args!("END"))
    }

    fn emit_imports(&mut self, imports: &Imports) -> io::Result<()> {
        if imports.by_module.is_empty() {
            return Ok(());
        }

        self.blank_line()?;
        self.line(0, format_args!("IMPORTS"))?;
        let last = imports.by_module.len().saturating_sub(1);
        for (index, (module, symbols)) in imports.by_module.iter().enumerate() {
            self.line(1, format_args!("{}", join_symbols(symbols)))?;
            let terminator = if index == last { ";" } else { "" };
            self.line(2, format_args!("FROM {module}{terminator}"))?;
        }
        Ok(())
    }

    fn emit_module_identity(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        identity: &ModuleIdentityData,
    ) -> io::Result<()> {
        self.line(0, format_args!("{} MODULE-IDENTITY", identity.name()))?;
        if !identity.last_updated().is_empty() {
            self.line(
                1,
                format_args!(
                    "LAST-UPDATED {}",
                    quoted(identity.last_updated(), &indentation(1))
                ),
            )?;
        }
        if !identity.organization().is_empty() {
            self.quoted_clause(1, "ORGANIZATION", identity.organization())?;
        }
        if !identity.contact_info().is_empty() {
            self.quoted_clause(1, "CONTACT-INFO", identity.contact_info())?;
        }
        self.description_clause(1, identity.description(), false)?;

        for revision in identity.revisions() {
            self.line(
                1,
                format_args!("REVISION {}", quoted(&revision.date, &indentation(1))),
            )?;
            self.description_clause(1, &revision.description, true)?;
        }

        self.line(
            1,
            format_args!("::= {}", oid_assignment(module, definitions, identity)),
        )
    }

    fn emit_object_identity(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        identity: &ModuleIdentityData,
    ) -> io::Result<()> {
        self.line(0, format_args!("{} OBJECT-IDENTITY", identity.name()))?;
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(identity.status())),
        )?;
        self.description_clause(1, identity.description(), false)?;
        if !identity.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", identity.reference())?;
        }
        self.line(
            1,
            format_args!("::= {}", oid_assignment(module, definitions, identity)),
        )
    }

    fn emit_oid_assignment(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        identity: &ModuleIdentityData,
    ) -> io::Result<()> {
        self.line(
            0,
            format_args!(
                "{} OBJECT IDENTIFIER ::= {}",
                identity.name(),
                oid_assignment(module, definitions, identity)
            ),
        )
    }

    fn description_clause(
        &mut self,
        indent: usize,
        description: &str,
        optional: bool,
    ) -> io::Result<()> {
        if !self.options.descriptions || optional && description.is_empty() {
            return Ok(());
        }
        self.quoted_clause(indent, "DESCRIPTION", description)
    }

    fn quoted_clause(&mut self, indent: usize, keyword: &str, text: &str) -> io::Result<()> {
        self.line(indent, format_args!("{keyword}"))?;
        self.line(
            indent + 1,
            format_args!("{}", quoted(text, &indentation(indent + 1))),
        )
    }

    fn blank_line(&mut self) -> io::Result<()> {
        self.destination.write_all(b"\n")
    }

    fn line(&mut self, indent: usize, arguments: fmt::Arguments<'_>) -> io::Result<()> {
        for _ in 0..indent {
            self.destination.write_all(INDENT)?;
        }
        self.destination.write_fmt(arguments)?;
        self.destination.write_all(b"\n")
    }
}

fn join_symbols(symbols: &BTreeSet<String>) -> String {
    symbols
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn indentation(level: usize) -> String {
    " ".repeat(INDENT.len() * level)
}

fn quoted(text: &str, continuation_indent: &str) -> String {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut output = String::with_capacity(normalized.len() + 2);
    output.push('"');
    for (index, line) in normalized.split('\n').enumerate() {
        if index > 0 {
            output.push('\n');
            output.push_str(continuation_indent);
        }
        let line = if index == 0 {
            line
        } else {
            line.trim_start_matches([' ', '\t'])
        };
        output.push_str(&line.replace('"', "\"\""));
    }
    output.push('"');
    output
}

fn canonical_status(status: Option<Status>) -> &'static str {
    match status.unwrap_or_default() {
        Status::Current | Status::Mandatory => "current",
        Status::Deprecated => "deprecated",
        Status::Obsolete => "obsolete",
        Status::Optional => "deprecated",
    }
}

enum AssignmentParent<'a> {
    Root,
    Local(&'a str),
    External { module: &'a str, name: &'a str },
    Numeric(Oid),
}

fn assignment_parent<'a>(
    module: Module<'a>,
    definitions: &'a Definitions<'a>,
    identity: &'a ModuleIdentityData,
) -> AssignmentParent<'a> {
    let Some(parent_oid) = identity.oid().parent() else {
        return AssignmentParent::Root;
    };
    if let Some(parent) = definitions.identity_at(&parent_oid) {
        return AssignmentParent::Local(parent.name());
    }

    if let Some(parent) = module.mib.exact_node_by_oid(&parent_oid)
        && !parent.name().is_empty()
        && let Some(parent_module) = parent.module()
        && parent_module.name() != module.name()
    {
        return AssignmentParent::External {
            module: parent_module.name(),
            name: parent.name(),
        };
    }

    AssignmentParent::Numeric(parent_oid)
}

fn oid_assignment(
    module: Module<'_>,
    definitions: &Definitions<'_>,
    identity: &ModuleIdentityData,
) -> String {
    let arc = identity.oid().last_arc().unwrap_or_default();
    match assignment_parent(module, definitions, identity) {
        AssignmentParent::Root => format!("{{ {arc} }}"),
        AssignmentParent::Local(name) | AssignmentParent::External { name, .. } => {
            format!("{{ {name} {arc} }}")
        }
        AssignmentParent::Numeric(parent) => {
            let parent = parent
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            format!("{{ {parent} {arc} }}")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::{DiagnosticConfig, Loader, source};

    #[test]
    fn options_default_to_all_output_families() {
        let options = Options::default();
        assert!(options.descriptions());
        assert!(options.conformance());
        assert!(options.reconstructed_sequences());

        let disabled = options
            .with_descriptions(false)
            .with_conformance(false)
            .with_reconstructed_sequences(false);
        assert!(!disabled.descriptions());
        assert!(!disabled.conformance());
        assert!(!disabled.reconstructed_sequences());
    }

    #[test]
    fn quoted_text_escapes_double_quotes() {
        assert_eq!(
            quoted("the \"quoted\" value", ""),
            r#""the ""quoted"" value""#
        );
    }

    #[test]
    fn io_error_retains_the_source_error() {
        let error = io::Error::new(io::ErrorKind::BrokenPipe, "closed");
        let writer_error = Error::from(error);
        assert!(matches!(writer_error, Error::Io(_)));
        assert_eq!(
            writer_error.to_string(),
            "failed to write canonical MIB: closed"
        );
    }

    #[test]
    fn definitions_build_one_deterministic_parent_entry_per_oid() {
        const ALIAS_COUNT: usize = 256;

        let mut input = String::from(
            r#"INDEXED-PARENTS-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
indexedParentsMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Index test"
    CONTACT-INFO "Index test"
    DESCRIPTION "Index test."
    ::= { enterprises 424290 }
"#,
        );
        for index in (0..ALIAS_COUNT).rev() {
            input.push_str(&format!(
                r#"alias{index:03} OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "Alias {index}."
    ::= {{ indexedParentsMib 1 }}
"#,
            ));
        }
        input.push_str("END\n");

        let mib = Loader::new()
            .source(source::memory("INDEXED-PARENTS-MIB", input.into_bytes()))
            .diagnostic_config(DiagnosticConfig::silent())
            .modules(["INDEXED-PARENTS-MIB"])
            .load()
            .expect("shared-OID alias module should load");
        let definitions = Definitions::collect(mib.module("INDEXED-PARENTS-MIB").unwrap());

        assert_eq!(definitions.module_identities.len(), 1);
        assert_eq!(definitions.oid_assignments.len(), ALIAS_COUNT);
        assert_eq!(definitions.identity_by_oid.len(), 2);
        let shared_oid: Oid = "1.3.6.1.4.1.424290.1".parse().unwrap();
        assert_eq!(
            definitions.identity_at(&shared_oid).unwrap().name(),
            "alias000"
        );
    }
}
