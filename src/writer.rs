//! Canonical SMIv2 output for resolved MIB modules.
//!
//! The writer emits one selected module from a resolved [`Mib`] to an
//! arbitrary [`std::io::Write`] destination. Output ordering, imports, and
//! indentation are deterministic.
//!
//! The writer currently emits identities, type definitions, `OBJECT-TYPE`
//! definitions, and reconstructed table `SEQUENCE` definitions. Notification
//! and conformance families are not emitted yet.
//! Resolved quoted-text values are preserved exactly, including multiline
//! whitespace and line endings; embedded quotes use ASN.1 doubled-quote
//! escaping.
//!
//! Writes are streaming and non-atomic. If the destination returns an I/O
//! error, it may already contain a prefix of the module.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use crate::mib::{DefValValue, NamedValue, OidRef, Range};
use crate::{
    Access, BaseType, Kind, Mib, Module, ModuleIdentityData, ModuleIdentityKind, Object, Oid,
    Status, Type,
};

const INDENT: &[u8] = b"    ";

/// Options controlling canonical module output.
///
/// All output families are enabled by default.
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
    ///
    /// Disabling them leaves table and row `SYNTAX` references intact but
    /// omits their structural type declarations. `mib-rs` can reparse that
    /// normalized subset from resolved object structure, while standalone
    /// ASN.1/SMI compilers may reject the undefined entry type names.
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
    /// A resolved definition cannot be represented by the writer's canonical
    /// SMIv2 subset without inventing or losing semantics.
    #[error("cannot write {definition}: {reason}")]
    UnsupportedDefinition {
        /// Name of the definition that cannot be emitted.
        definition: String,
        /// Reason the resolved definition is unsupported.
        reason: String,
    },
    /// The output destination rejected a write.
    #[error("failed to write canonical MIB: {0}")]
    Io(#[from] io::Error),
}

/// Write one resolved module using default [`Options`].
///
/// # Errors
///
/// Returns [`Error::ModuleNotFound`] when `module_name` is not loaded and
/// [`Error::UnsupportedDefinition`] when a resolved definition cannot be
/// represented faithfully. Both are detected before writing. Returns
/// [`Error::Io`] when the destination rejects a write; an I/O error may leave
/// a partial module in the destination.
pub fn write<W: Write>(destination: W, mib: &Mib, module_name: &str) -> Result<(), Error> {
    write_with_options(destination, mib, module_name, Options::default())
}

/// Write one resolved module using explicit [`Options`].
///
/// # Errors
///
/// Returns [`Error::ModuleNotFound`] when `module_name` is not loaded and
/// [`Error::UnsupportedDefinition`] when a resolved definition cannot be
/// represented faithfully. Both are detected before writing. Returns
/// [`Error::Io`] when the destination rejects a write; an I/O error may leave
/// a partial module in the destination.
pub fn write_with_options<W: Write>(
    destination: W,
    mib: &Mib,
    module_name: &str,
    options: Options,
) -> Result<(), Error> {
    let module = mib
        .module(module_name)
        .ok_or_else(|| Error::ModuleNotFound(module_name.to_owned()))?;
    let definitions = Definitions::collect(module);
    definitions.validate(module)?;
    Emitter::new(destination, options).emit_module(module, &definitions)?;
    Ok(())
}

struct Definitions<'a> {
    module_identities: Vec<&'a ModuleIdentityData>,
    types: Vec<Type<'a>>,
    oid_assignments: Vec<&'a ModuleIdentityData>,
    objects: Vec<Object<'a>>,
    rows: Vec<Object<'a>>,
    object_by_name: BTreeMap<&'a str, Object<'a>>,
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

        let mut types = module.types().collect::<Vec<_>>();
        types.sort_by_key(|typ| typ.name());

        let mut objects = module.objects().collect::<Vec<_>>();
        objects.sort_by(|left, right| {
            object_oid(*left)
                .cmp(&object_oid(*right))
                .then_with(|| left.name().cmp(right.name()))
        });
        let rows = objects
            .iter()
            .copied()
            .filter(|object| object.declared_kind() == Kind::Row)
            .collect();
        let object_by_name = objects
            .iter()
            .map(|object| (object.name(), *object))
            .collect();

        Self {
            module_identities,
            types,
            oid_assignments,
            objects,
            rows,
            object_by_name,
        }
    }

    fn validate(&self, module: Module<'_>) -> Result<(), Error> {
        for identity in self.module_identities.iter().chain(&self.oid_assignments) {
            validate_oid_anchor(module, identity.name(), identity.oid(), identity.oid_refs())?;
        }
        for typ in &self.types {
            validate_type(*typ)?;
        }
        for object in &self.objects {
            if let Some(node) = object.node() {
                validate_oid_anchor(module, object.name(), node.oid(), object.oid_refs())?;
            }
            validate_object(self, *object)?;
            if let Some(default) = object.default_value()
                && let DefValValue::Oid(oid) = default.value()
                && !default.oid_ref().is_some_and(|reference| {
                    reference.oid() == Some(oid) && reference.module_id().is_some()
                })
            {
                return Err(unsupported(
                    object.name(),
                    "contains an OID DEFVAL without a symbolic anchor",
                ));
            }
        }
        Ok(())
    }

    fn exact_row(&self, table: Object<'a>) -> Option<Object<'a>> {
        self.object_by_name.get(table.declared_row_name()).copied()
    }

    fn exact_table(&self, row: Object<'a>) -> Option<Object<'a>> {
        self.object_by_name.get(row.declared_table_name()).copied()
    }

    fn exact_columns(&self, row: Object<'a>) -> Vec<Object<'a>> {
        row.declared_column_names()
            .iter()
            .filter_map(|name| self.object_by_name.get(name.as_str()).copied())
            .collect()
    }
}

fn validate_oid_anchor(
    _module: Module<'_>,
    definition: &str,
    oid: &Oid,
    references: &[OidRef],
) -> Result<(), Error> {
    if references.is_empty() {
        return Ok(());
    }
    let Some(anchor) = declared_anchor(oid, references) else {
        return Err(unsupported(
            definition,
            "contains a symbolic OID anchor whose provenance could not be recovered",
        ));
    };
    if anchor.module_id().is_none() {
        return Err(unsupported(
            definition,
            "contains a symbolic OID anchor without an exact defining module version",
        ));
    }
    Ok(())
}

fn object_oid(object: Object<'_>) -> Option<&Oid> {
    object.node().map(|node| node.oid())
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
            "MODULE-IDENTITY" | "OBJECT-IDENTITY" | "OBJECT-TYPE" => "SNMPv2-SMI",
            "TEXTUAL-CONVENTION" => "SNMPv2-TC",
            _ => return,
        };
        self.add(module, name);
    }

    fn add_type(&mut self, typ: Type<'_>) {
        if is_foundation_smiv1_type_alias(typ) {
            self.add_base_type(typ.effective_base());
            return;
        }
        if is_builtin_type_name(typ.name()) {
            return;
        }
        if let Some(module) = typ.module() {
            self.add(module.name(), typ.name());
        }
    }

    fn add_base_type(&mut self, base: BaseType) {
        let name = match base {
            BaseType::Integer32 => "Integer32",
            BaseType::Unsigned32 => "Unsigned32",
            BaseType::Counter32 => "Counter32",
            BaseType::Counter64 => "Counter64",
            BaseType::Gauge32 => "Gauge32",
            BaseType::TimeTicks => "TimeTicks",
            BaseType::IpAddress => "IpAddress",
            BaseType::Opaque => "Opaque",
            BaseType::OctetString | BaseType::ObjectIdentifier | BaseType::Bits => return,
            BaseType::Unknown | BaseType::Sequence | BaseType::Integer64 | BaseType::Unsigned64 => {
                return;
            }
        };
        self.add("SNMPv2-SMI", name);
    }

    fn add_oid_ref(&mut self, module: Module<'_>, reference: &OidRef) {
        if let Some(module_id) = reference.module_id() {
            let source = module.mib.raw().module(module_id).name();
            self.add(source, &reference.name);
        }
    }

    fn add_type_syntax(&mut self, typ: Type<'_>, enums: &[NamedValue], bits: &[NamedValue]) {
        if !enums.is_empty() || !bits.is_empty() {
            if let Some(parent) = typ.parent()
                && !is_builtin_type_name(parent.name())
            {
                self.add_type(parent);
            }
            return;
        }
        if let Some(parent) = typ.parent() {
            self.add_type(parent);
        } else {
            self.add_base_type(typ.effective_base());
        }
    }

    fn collect(module: Module<'_>, definitions: &Definitions<'_>) -> Self {
        let mut imports = Self::new(module.name());
        for identity in &definitions.module_identities {
            imports.add_macro("MODULE-IDENTITY");
            if let Some(reference) = declared_anchor(identity.oid(), identity.oid_refs()) {
                imports.add_oid_ref(module, reference);
            }
        }
        for identity in &definitions.oid_assignments {
            if identity.kind() == ModuleIdentityKind::ObjectIdentity {
                imports.add_macro("OBJECT-IDENTITY");
            }
            if let Some(reference) = declared_anchor(identity.oid(), identity.oid_refs()) {
                imports.add_oid_ref(module, reference);
            }
        }
        for typ in &definitions.types {
            imports.add_macro("TEXTUAL-CONVENTION");
            imports.add_type_syntax(*typ, typ.enums(), typ.bits());
        }
        for object in &definitions.objects {
            imports.add_macro("OBJECT-TYPE");
            if let Some(node) = object.node()
                && let Some(reference) = declared_anchor(node.oid(), object.oid_refs())
            {
                imports.add_oid_ref(module, reference);
            }
            if !matches!(object.declared_kind(), Kind::Table | Kind::Row)
                && let Some(typ) = object.ty()
            {
                if !typ.name().is_empty() && !is_builtin_type_name(typ.name()) {
                    imports.add_type(typ);
                } else {
                    imports.add_type_syntax(typ, object.effective_enums(), object.effective_bits());
                }
            }
            for index in object.index() {
                if let Some(index_object) = index.object()
                    && let Some(index_module) = index_object.module()
                {
                    imports.add(index_module.name(), index_object.name());
                } else if let Some(index_type) = index.ty() {
                    imports.add_type(index_type);
                }
            }
            if let Some(augment) = object.augments()
                && let Some(augment_module) = augment.module()
            {
                imports.add(augment_module.name(), augment.name());
            }
            if let Some(default) = object.default_value()
                && matches!(default.value(), DefValValue::Oid(_))
                && let Some(reference) = default.oid_ref()
            {
                imports.add_oid_ref(module, reference);
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

    fn emit_module(&mut self, module: Module<'_>, definitions: &Definitions<'_>) -> io::Result<()> {
        let imports = Imports::collect(module, definitions);

        self.line(0, format_args!("{} DEFINITIONS ::= BEGIN", module.name()))?;
        self.emit_imports(&imports)?;

        for identity in &definitions.module_identities {
            self.blank_line()?;
            self.emit_module_identity(module, definitions, identity)?;
        }

        for typ in &definitions.types {
            self.blank_line()?;
            self.emit_type(*typ)?;
        }

        for identity in &definitions.oid_assignments {
            self.blank_line()?;
            match identity.kind() {
                ModuleIdentityKind::ObjectIdentity => {
                    self.emit_object_identity(module, definitions, identity)?;
                }
                ModuleIdentityKind::ObjectIdentifier => {
                    self.emit_oid_assignment(module, definitions, identity)?;
                }
                ModuleIdentityKind::ModuleIdentity => {}
            }
        }

        for object in &definitions.objects {
            self.blank_line()?;
            self.emit_object(module, definitions, *object)?;
        }

        if self.options.reconstructed_sequences {
            for row in &definitions.rows {
                self.blank_line()?;
                self.emit_sequence(definitions, *row)?;
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
                format_args!("LAST-UPDATED {}", quoted(identity.last_updated())),
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
            self.line(1, format_args!("REVISION {}", quoted(&revision.date)))?;
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

    fn emit_type(&mut self, typ: Type<'_>) -> io::Result<()> {
        self.line(0, format_args!("{} ::= TEXTUAL-CONVENTION", typ.name()))?;
        if !typ.display_hint().is_empty() {
            self.line(
                1,
                format_args!("DISPLAY-HINT {}", quoted(typ.display_hint())),
            )?;
        }
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(Some(typ.status()))),
        )?;
        self.description_clause(1, typ.description(), false)?;
        if !typ.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", typ.reference())?;
        }
        self.line(1, format_args!("SYNTAX {}", type_syntax(typ)))
    }

    fn emit_object(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        object: Object<'_>,
    ) -> io::Result<()> {
        self.line(0, format_args!("{} OBJECT-TYPE", object.name()))?;
        self.line(
            1,
            format_args!("SYNTAX {}", object_syntax(definitions, object)),
        )?;
        if !object.units().is_empty() {
            self.line(1, format_args!("UNITS {}", quoted(object.units())))?;
        }
        self.line(
            1,
            format_args!("MAX-ACCESS {}", canonical_access(object.access())),
        )?;
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(Some(object.status()))),
        )?;
        self.description_clause(1, object.description(), false)?;
        if !object.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", object.reference())?;
        }
        if object.declared_kind() == Kind::Row {
            if let Some(augment) = object.augments() {
                self.line(1, format_args!("AUGMENTS {{ {} }}", augment.name()))?;
            } else {
                let indexes = object.index().collect::<Vec<_>>();
                if !indexes.is_empty() {
                    let indexes = indexes
                        .iter()
                        .map(|index| {
                            if index.implied() {
                                format!("IMPLIED {}", index.name())
                            } else {
                                index.name().to_owned()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    self.line(1, format_args!("INDEX {{ {indexes} }}"))?;
                }
            }
        }
        if let Some(default) = object.default_value()
            && !default.is_unset()
        {
            self.line(
                1,
                format_args!(
                    "DEFVAL {{ {} }}",
                    defval_syntax(module, definitions, default)
                ),
            )?;
        }
        let oid = object.node().expect("validated object node").oid();
        self.line(
            1,
            format_args!(
                "::= {}",
                object_oid_assignment(module, definitions, object, oid)
            ),
        )
    }

    fn emit_sequence(&mut self, definitions: &Definitions<'_>, row: Object<'_>) -> io::Result<()> {
        let columns = definitions.exact_columns(row);
        self.line(
            0,
            format_args!("{} ::= SEQUENCE {{", sequence_name(definitions, row)),
        )?;
        for (index, column) in columns.iter().enumerate() {
            let comma = if index + 1 == columns.len() { "" } else { "," };
            self.line(
                1,
                format_args!("{} {}{comma}", column.name(), sequence_field_type(*column)),
            )?;
        }
        self.line(0, format_args!("}}"))
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
        self.line(indent + 1, format_args!("{}", quoted(text)))
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

fn quoted(text: &str) -> String {
    let mut output = String::with_capacity(text.len() + 2);
    output.push('"');
    for character in text.chars() {
        if character == '"' {
            output.push('"');
        }
        output.push(character);
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

fn canonical_access(access: Access) -> &'static str {
    match access {
        Access::NotAccessible => "not-accessible",
        Access::AccessibleForNotify => "accessible-for-notify",
        Access::ReadOnly => "read-only",
        Access::ReadWrite | Access::WriteOnly => "read-write",
        Access::ReadCreate => "read-create",
        Access::NotImplemented => unreachable!("validated object access"),
    }
}

fn oid_assignment(
    _module: Module<'_>,
    _definitions: &Definitions<'_>,
    identity: &ModuleIdentityData,
) -> String {
    oid_assignment_from_refs(identity.oid(), identity.oid_refs())
}

fn declared_anchor<'a>(oid: &Oid, references: &'a [OidRef]) -> Option<&'a OidRef> {
    references
        .iter()
        .filter(|reference| {
            reference
                .oid()
                .is_some_and(|anchor| oid.starts_with(anchor))
        })
        .max_by_key(|reference| reference.oid().map_or(0, |oid| oid.len()))
}

fn oid_assignment_from_refs(oid: &Oid, references: &[OidRef]) -> String {
    if let Some(reference) = declared_anchor(oid, references) {
        let anchor_len = reference.oid().map_or(0, |oid| oid.len());
        let suffix = oid[anchor_len..]
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ");
        if suffix.is_empty() {
            format!("{{ {} }}", reference.name)
        } else {
            format!("{{ {} {suffix} }}", reference.name)
        }
    } else {
        let numeric = oid.iter().map(u32::to_string).collect::<Vec<_>>().join(" ");
        format!("{{ {numeric} }}")
    }
}

fn object_oid_assignment(
    _module: Module<'_>,
    _definitions: &Definitions<'_>,
    object: Object<'_>,
    oid: &Oid,
) -> String {
    oid_assignment_from_refs(oid, object.oid_refs())
}

fn is_builtin_type_name(name: &str) -> bool {
    matches!(
        name,
        "INTEGER" | "OCTET STRING" | "OBJECT IDENTIFIER" | "BITS" | "NULL" | "SEQUENCE"
    )
}

fn is_foundation_smiv1_type_alias(typ: Type<'_>) -> bool {
    matches!(typ.name(), "Counter" | "Gauge" | "NetworkAddress")
        && typ
            .module()
            .is_some_and(|module| matches!(module.name(), "RFC1155-SMI" | "RFC1065-SMI"))
}

fn canonical_type_name(typ: Type<'_>) -> &str {
    if !is_foundation_smiv1_type_alias(typ) {
        return typ.name();
    }
    match typ.name() {
        "Counter" => "Counter32",
        "Gauge" => "Gauge32",
        "NetworkAddress" => "IpAddress",
        name => name,
    }
}

fn base_type_syntax(base: BaseType) -> &'static str {
    match base {
        BaseType::Integer32 => "Integer32",
        BaseType::Unsigned32 => "Unsigned32",
        BaseType::Counter32 => "Counter32",
        BaseType::Counter64 => "Counter64",
        BaseType::Gauge32 => "Gauge32",
        BaseType::TimeTicks => "TimeTicks",
        BaseType::IpAddress => "IpAddress",
        BaseType::OctetString => "OCTET STRING",
        BaseType::ObjectIdentifier => "OBJECT IDENTIFIER",
        BaseType::Bits => "BITS",
        BaseType::Opaque => "Opaque",
        BaseType::Unknown | BaseType::Sequence | BaseType::Integer64 | BaseType::Unsigned64 => {
            unreachable!("validated base type")
        }
    }
}

fn format_named_values(values: &[NamedValue]) -> String {
    let body = values
        .iter()
        .map(|value| format!("{}({})", value.label, value.value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{ {body} }}")
}

fn format_ranges(ranges: &[Range]) -> String {
    ranges
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" | ")
}

fn constrained_syntax(prefix: &str, ranges: &[Range], sizes: &[Range]) -> String {
    if !sizes.is_empty() {
        format!("{prefix} (SIZE ({}))", format_ranges(sizes))
    } else if !ranges.is_empty() {
        format!("{prefix} ({})", format_ranges(ranges))
    } else {
        prefix.to_owned()
    }
}

fn type_syntax(typ: Type<'_>) -> String {
    if !typ.bits().is_empty() {
        let base = typ
            .parent()
            .filter(|parent| !parent.name().is_empty() && !is_builtin_type_name(parent.name()))
            .map_or("BITS", canonical_type_name);
        let prefix = format!("{base} {}", format_named_values(typ.bits()));
        return constrained_syntax(&prefix, typ.ranges(), typ.sizes());
    }
    if !typ.enums().is_empty() {
        let base = typ
            .parent()
            .filter(|parent| !parent.name().is_empty() && !is_builtin_type_name(parent.name()))
            .map_or("INTEGER", canonical_type_name);
        let prefix = format!("{base} {}", format_named_values(typ.enums()));
        return constrained_syntax(&prefix, typ.ranges(), typ.sizes());
    }
    let prefix = typ
        .parent()
        .filter(|parent| !parent.name().is_empty())
        .map_or_else(
            || base_type_syntax(typ.effective_base()),
            canonical_type_name,
        );
    constrained_syntax(prefix, typ.ranges(), typ.sizes())
}

fn object_syntax(definitions: &Definitions<'_>, object: Object<'_>) -> String {
    match object.declared_kind() {
        Kind::Table => {
            let row = definitions.exact_row(object).expect("validated table row");
            format!("SEQUENCE OF {}", sequence_name(definitions, row))
        }
        Kind::Row => sequence_name(definitions, object),
        _ => {
            let typ = object.ty().expect("validated object type");
            if !object.declared_bits().is_empty() {
                let base = if !typ.name().is_empty() && !is_builtin_type_name(typ.name()) {
                    canonical_type_name(typ)
                } else {
                    "BITS"
                };
                let prefix = format!("{base} {}", format_named_values(object.declared_bits()));
                return constrained_syntax(
                    &prefix,
                    object.declared_ranges(),
                    object.declared_sizes(),
                );
            }
            if !object.declared_enums().is_empty() {
                let prefix = format!(
                    "{} {}",
                    canonical_type_name(typ),
                    format_named_values(object.declared_enums())
                );
                return constrained_syntax(
                    &prefix,
                    object.declared_ranges(),
                    object.declared_sizes(),
                );
            }
            if !typ.name().is_empty() && !is_builtin_type_name(typ.name()) {
                return constrained_syntax(
                    canonical_type_name(typ),
                    object.declared_ranges(),
                    object.declared_sizes(),
                );
            }
            let prefix = typ
                .parent()
                .filter(|parent| !parent.name().is_empty())
                .map_or_else(
                    || base_type_syntax(typ.effective_base()),
                    canonical_type_name,
                );
            constrained_syntax(prefix, object.declared_ranges(), object.declared_sizes())
        }
    }
}

fn sequence_name(definitions: &Definitions<'_>, row: Object<'_>) -> String {
    if let Some(table) = definitions.exact_table(row)
        && !table.sequence_type_name().is_empty()
    {
        return table.sequence_type_name().to_owned();
    }
    capitalize_identifier(row.name())
}

fn capitalize_identifier(name: &str) -> String {
    let mut bytes = name.as_bytes().to_vec();
    if let Some(first) = bytes.first_mut() {
        first.make_ascii_uppercase();
    }
    String::from_utf8(bytes).expect("SMI identifiers are ASCII")
}

fn sequence_field_type(column: Object<'_>) -> String {
    let typ = column.ty().expect("validated column type");
    if !typ.name().is_empty() {
        return canonical_type_name(typ).to_owned();
    }
    if let Some(parent) = typ.parent()
        && !parent.name().is_empty()
    {
        return canonical_type_name(parent).to_owned();
    }
    base_type_syntax(typ.effective_base()).to_owned()
}

fn defval_syntax(
    _module: Module<'_>,
    _definitions: &Definitions<'_>,
    default: &crate::mib::DefVal,
) -> String {
    match default.value() {
        DefValValue::None => String::new(),
        DefValValue::Int(value) => value.to_string(),
        DefValValue::Uint(value) => value.to_string(),
        DefValValue::String(value) => quoted(value),
        DefValValue::Bytes(_) => default.raw().to_owned(),
        DefValValue::Enum(label) => label.clone(),
        DefValValue::Bits(labels) => format!("{{ {} }}", labels.join(", ")),
        DefValValue::Oid(_) => default
            .oid_ref()
            .expect("validated OID DEFVAL anchor")
            .name
            .clone(),
    }
}

fn validate_ranges(definition: &str, ranges: &[Range]) -> Result<(), Error> {
    for range in ranges {
        if matches!(range.min, crate::mib::RangeBound::Raw(_))
            || matches!(range.max, crate::mib::RangeBound::Raw(_))
        {
            return Err(unsupported(
                definition,
                "contains an unresolved constraint bound",
            ));
        }
    }
    Ok(())
}

fn validate_base(definition: &str, base: BaseType) -> Result<(), Error> {
    match base {
        BaseType::Unknown => Err(unsupported(definition, "has an unresolved type")),
        BaseType::Sequence => Err(unsupported(
            definition,
            "uses a non-reconstructed SEQUENCE type",
        )),
        BaseType::Integer64 | BaseType::Unsigned64 => Err(unsupported(
            definition,
            "uses an SPPI type with no canonical SMIv2 representation",
        )),
        _ => Ok(()),
    }
}

fn validate_type(typ: Type<'_>) -> Result<(), Error> {
    if typ.name().is_empty() {
        return Err(unsupported("unnamed type", "has no declaration name"));
    }
    validate_base(typ.name(), typ.effective_base())?;
    validate_ranges(typ.name(), typ.ranges())?;
    validate_ranges(typ.name(), typ.sizes())
}

fn validate_object(definitions: &Definitions<'_>, object: Object<'_>) -> Result<(), Error> {
    let name = object.name();
    if !object.data().declared_structure_error().is_empty() {
        return Err(unsupported(name, object.data().declared_structure_error()));
    }
    if object.node().is_none() {
        return Err(unsupported(name, "has no resolved OID"));
    }
    if object.access() == Access::NotImplemented {
        return Err(unsupported(
            name,
            "uses AGENT-CAPABILITIES not-implemented access",
        ));
    }
    match object.declared_kind() {
        Kind::Table => {
            if definitions.exact_row(object).is_none() {
                return Err(unsupported(name, "has no resolved row object"));
            }
        }
        Kind::Row => {
            if definitions.exact_table(object).is_none() {
                return Err(unsupported(name, "has no resolved table object"));
            }
            if object.data().augments_range().is_some() && object.augments().is_none() {
                return Err(unsupported(name, "contains an unresolved AUGMENTS target"));
            }
            if object.index().next().is_none() && object.augments().is_none() {
                return Err(unsupported(
                    name,
                    "declares a row without INDEX or AUGMENTS",
                ));
            }
            for index in object.index() {
                if index.name().is_empty() || index.object().is_none() && index.ty().is_none() {
                    return Err(unsupported(name, "contains an unresolved INDEX component"));
                }
                if index.object().is_none() {
                    return Err(unsupported(name, "uses an SMIv1 bare-type INDEX component"));
                }
            }
        }
        Kind::Scalar | Kind::Column => {
            let typ = object
                .ty()
                .ok_or_else(|| unsupported(name, "has no resolved type"))?;
            validate_base(name, typ.effective_base())?;
            validate_ranges(name, object.declared_ranges())?;
            validate_ranges(name, object.declared_sizes())?;
        }
        kind => {
            return Err(unsupported(
                name,
                &format!("has non-OBJECT-TYPE node kind {kind}"),
            ));
        }
    }
    if object
        .default_value()
        .is_some_and(crate::mib::DefVal::is_unset)
    {
        return Err(unsupported(name, "contains an unresolved DEFVAL"));
    }
    if object
        .ty()
        .is_some_and(|typ| typ.effective_base() == BaseType::ObjectIdentifier)
        && object
            .default_value()
            .is_some_and(|default| !matches!(default.value(), DefValValue::Oid(_)))
    {
        return Err(unsupported(name, "contains an unresolved OID DEFVAL"));
    }
    if let Some(default) = object.default_value()
        && let DefValValue::Oid(oid) = default.value()
        && oid.is_empty()
    {
        return Err(unsupported(name, "contains an empty OID DEFVAL"));
    }
    if let Some(default) = object.default_value()
        && let DefValValue::Bytes(_) = default.value()
        && !valid_byte_defval(default.raw())
    {
        return Err(unsupported(name, "contains a malformed byte-string DEFVAL"));
    }
    Ok(())
}

fn valid_byte_defval(raw: &str) -> bool {
    let Some((quoted, suffix)) = raw.rsplit_once('\'') else {
        return false;
    };
    let Some(content) = quoted.strip_prefix('\'') else {
        return false;
    };
    match suffix {
        "H" | "h" => content
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character.is_ascii_whitespace()),
        "B" | "b" => content
            .chars()
            .all(|character| matches!(character, '0' | '1') || character.is_ascii_whitespace()),
        _ => false,
    }
}

fn unsupported(definition: &str, reason: &str) -> Error {
    Error::UnsupportedDefinition {
        definition: definition.to_owned(),
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

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
        assert_eq!(quoted("the \"quoted\" value"), r#""the ""quoted"" value""#);
    }

    #[test]
    fn quoted_text_preserves_multiline_whitespace_and_line_endings() {
        assert_eq!(
            quoted("first\n  second\r\n\tthird"),
            "\"first\n  second\r\n\tthird\""
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
    fn definitions_collect_all_shared_oid_aliases_deterministically() {
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
        assert_eq!(definitions.oid_assignments[0].name(), "alias000");
        assert_eq!(
            definitions.oid_assignments[ALIAS_COUNT - 1].name(),
            "alias255"
        );
    }

    #[test]
    fn oid_anchor_provenance_keeps_the_selected_module_version() {
        let inputs: [(&str, &[u8]); 4] = [
            (
                "embedded:SNMPv2-SMI",
                crate::lower::base_modules::embedded_content("SNMPv2-SMI").unwrap(),
            ),
            (
                "first",
                br#"DUPLICATE-ANCHOR-MIB DEFINITIONS ::= BEGIN
IMPORTS iso FROM SNMPv2-SMI;
aRoot OBJECT IDENTIFIER ::= { iso 3 6 1 4 1 424300 }
END
"#,
            ),
            (
                "second",
                br#"DUPLICATE-ANCHOR-MIB DEFINITIONS ::= BEGIN
IMPORTS iso FROM SNMPv2-SMI;
bRoot OBJECT IDENTIFIER ::= { iso 3 6 1 4 1 424300 }
END
"#,
            ),
            (
                "consumer",
                br#"VERSION-ANCHOR-CONSUMER-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE FROM SNMPv2-SMI bRoot FROM DUPLICATE-ANCHOR-MIB;
versionObject OBJECT-TYPE SYNTAX OBJECT IDENTIFIER MAX-ACCESS read-only STATUS current DESCRIPTION "Version." DEFVAL { bRoot } ::= { bRoot 1 }
END
"#,
            ),
        ];
        let mut sources = crate::source::SourceSet::new();
        let ids = inputs
            .iter()
            .map(|(label, bytes)| {
                sources
                    .insert(
                        crate::source::SourceOrigin::memory(*label),
                        *label,
                        Arc::from(*bytes),
                    )
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let config = DiagnosticConfig::silent();
        let modules = ids
            .iter()
            .flat_map(|source_id| {
                let document = sources.get(*source_id).unwrap();
                crate::parser::parse(document, &config)
                    .into_iter()
                    .map(|module| crate::lower::lower(module, document, &config))
                    .collect::<Vec<_>>()
            })
            .collect();
        let mib = crate::mib::resolver::resolve(
            modules,
            sources,
            crate::ResolverStrictness::Strict,
            &config,
        );
        let consumer = mib.module("VERSION-ANCHOR-CONSUMER-MIB").unwrap();
        let selected = consumer.import_source("bRoot").unwrap();
        let object = consumer.object("versionObject").unwrap();
        assert_eq!(
            object.declared_oid_parent().unwrap().module_id(),
            Some(selected.id())
        );
        assert_eq!(
            object
                .default_value()
                .unwrap()
                .oid_ref()
                .unwrap()
                .module_id(),
            Some(selected.id())
        );

        let mut output = Vec::new();
        write(&mut output, &mib, "VERSION-ANCHOR-CONSUMER-MIB").unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("bRoot\n        FROM DUPLICATE-ANCHOR-MIB"));
        assert!(output.contains("DEFVAL { bRoot }"));
        assert!(output.contains("::= { bRoot 1 }"));
    }
}
