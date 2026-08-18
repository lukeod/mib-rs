//! Canonical SMIv2 output for resolved MIB modules.
//!
//! The writer emits one selected module from a resolved [`Mib`] to an
//! arbitrary [`std::io::Write`] destination. Output ordering, imports, and
//! indentation are deterministic.
//!
//! The writer emits identities, type definitions, `OBJECT-TYPE` and
//! `NOTIFICATION-TYPE` definitions, conformance definitions, and reconstructed
//! table `SEQUENCE` definitions. SMIv1 traps are normalized to
//! `NOTIFICATION-TYPE`.
//! Resolved quoted-text values are preserved exactly, including multiline
//! whitespace and line endings; embedded quotes use ASN.1 doubled-quote
//! escaping.
//!
//! Writes are streaming and non-atomic. If the destination returns an I/O
//! error, it may already contain a prefix of the module.
//!
//! # Example
//!
//! ```no_run
//! use mib_rs::{Loader, writer};
//!
//! let mib = Loader::new()
//!     .system_paths()
//!     .modules(["IF-MIB"])
//!     .load()?;
//! let mut output = Vec::new();
//! writer::write(&mut output, &mib, "IF-MIB")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Write};

use crate::mib::{DefValValue, NamedValue, OidRef, Range, SyntaxConstraints};
use crate::{
    Access, BaseType, Capability, Compliance, Group, Kind, Mib, Module, ModuleIdentityData,
    ModuleIdentityKind, Notification, Object, Oid, Status, Type,
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
    definitions.validate(module, options)?;
    Emitter::new(destination, options).emit_module(module, &definitions)?;
    Ok(())
}

struct Definitions<'a> {
    module_identities: Vec<&'a ModuleIdentityData>,
    types: Vec<Type<'a>>,
    oid_assignments: Vec<&'a ModuleIdentityData>,
    objects: Vec<Object<'a>>,
    notifications: Vec<Notification<'a>>,
    groups: Vec<Group<'a>>,
    compliances: Vec<Compliance<'a>>,
    capabilities: Vec<Capability<'a>>,
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

        let mut notifications = module
            .data()
            .notifications()
            .iter()
            .copied()
            .map(|id| module.mib.notification_by_id(id))
            .collect::<Vec<_>>();
        notifications.sort_by(|left, right| {
            entity_order(left.node(), left.name(), right.node(), right.name())
        });

        let mut groups = module
            .data()
            .groups()
            .iter()
            .copied()
            .map(|id| module.mib.group_by_id(id))
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| {
            entity_order(left.node(), left.name(), right.node(), right.name())
        });

        let mut compliances = module
            .data()
            .compliances()
            .iter()
            .copied()
            .map(|id| module.mib.compliance_by_id(id))
            .collect::<Vec<_>>();
        compliances.sort_by(|left, right| {
            entity_order(left.node(), left.name(), right.node(), right.name())
        });

        let mut capabilities = module
            .data()
            .capabilities()
            .iter()
            .copied()
            .map(|id| module.mib.capability_by_id(id))
            .collect::<Vec<_>>();
        capabilities.sort_by(|left, right| {
            entity_order(left.node(), left.name(), right.node(), right.name())
        });

        Self {
            module_identities,
            types,
            oid_assignments,
            objects,
            notifications,
            groups,
            compliances,
            capabilities,
            rows,
            object_by_name,
        }
    }

    fn validate(&self, module: Module<'_>, options: Options) -> Result<(), Error> {
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
        for notification in &self.notifications {
            validate_entity_oid(
                module,
                notification.name(),
                notification.node(),
                notification.oid_refs(),
            )?;
        }
        if options.conformance {
            for group in &self.groups {
                validate_entity_oid(module, group.name(), group.node(), group.oid_refs())?;
            }
            for compliance in &self.compliances {
                validate_entity_oid(
                    module,
                    compliance.name(),
                    compliance.node(),
                    compliance.oid_refs(),
                )?;
                for clause in compliance.modules() {
                    if !clause.module_name.is_empty()
                        && module.mib.module(&clause.module_name).is_none()
                    {
                        return Err(unsupported(
                            compliance.name(),
                            "references an unresolved compliance module",
                        ));
                    }
                    for object in &clause.objects {
                        if let Some(syntax) = &object.syntax {
                            validate_syntax_constraints(module, compliance.name(), syntax)?;
                        }
                        if let Some(syntax) = &object.write_syntax {
                            validate_syntax_constraints(module, compliance.name(), syntax)?;
                        }
                    }
                }
            }
            for capability in &self.capabilities {
                validate_entity_oid(
                    module,
                    capability.name(),
                    capability.node(),
                    capability.oid_refs(),
                )?;
                for supports in capability.supports() {
                    if module.mib.module(&supports.module_name).is_none() {
                        return Err(unsupported(
                            capability.name(),
                            "references an unresolved supported module",
                        ));
                    }
                    for variation in &supports.object_variations {
                        if let Some(syntax) = &variation.syntax {
                            validate_syntax_constraints(module, capability.name(), syntax)?;
                        }
                        if let Some(syntax) = &variation.write_syntax {
                            validate_syntax_constraints(module, capability.name(), syntax)?;
                        }
                        if variation
                            .def_val
                            .as_ref()
                            .is_some_and(crate::mib::DefVal::is_unset)
                        {
                            return Err(unsupported(
                                capability.name(),
                                "contains an unresolved variation DEFVAL",
                            ));
                        }
                        validate_oid_default(capability.name(), variation.def_val.as_ref())?;
                    }
                }
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

    fn emits_oid_name(&self, name: &str, options: Options) -> bool {
        self.module_identities
            .iter()
            .chain(&self.oid_assignments)
            .any(|identity| identity.name() == name)
            || self.objects.iter().any(|object| object.name() == name)
            || self
                .notifications
                .iter()
                .any(|notification| notification.name() == name)
            || options.conformance
                && (self.groups.iter().any(|group| group.name() == name)
                    || self
                        .compliances
                        .iter()
                        .any(|compliance| compliance.name() == name)
                    || self
                        .capabilities
                        .iter()
                        .any(|capability| capability.name() == name))
    }
}

fn entity_order(
    left_node: Option<crate::mib::Node<'_>>,
    left_name: &str,
    right_node: Option<crate::mib::Node<'_>>,
    right_name: &str,
) -> std::cmp::Ordering {
    left_node
        .map(|node| node.oid())
        .cmp(&right_node.map(|node| node.oid()))
        .then_with(|| left_name.cmp(right_name))
}

fn validate_entity_oid(
    module: Module<'_>,
    name: &str,
    node: Option<crate::mib::Node<'_>>,
    references: &[OidRef],
) -> Result<(), Error> {
    let node = node.ok_or_else(|| unsupported(name, "has no resolved OID"))?;
    validate_oid_anchor(module, name, node.oid(), references)
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
            "MODULE-IDENTITY" | "OBJECT-IDENTITY" | "OBJECT-TYPE" | "NOTIFICATION-TYPE" => {
                "SNMPv2-SMI"
            }
            "TEXTUAL-CONVENTION" => "SNMPv2-TC",
            "OBJECT-GROUP" | "NOTIFICATION-GROUP" | "MODULE-COMPLIANCE" | "AGENT-CAPABILITIES" => {
                "SNMPv2-CONF"
            }
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

    fn add_constraints(&mut self, module: Module<'_>, constraints: &SyntaxConstraints) {
        if !constraints.bits.is_empty() {
            return;
        }
        if let Some(type_id) = constraints.type_id {
            let typ = module.mib.type_by_id(type_id);
            if constraints.enums.is_empty()
                || !typ.name().is_empty() && !is_builtin_type_name(typ.name())
            {
                self.add_type(typ);
            }
        }
    }

    fn add_node(&mut self, node: crate::mib::Node<'_>) {
        if let Some(source) = node.module() {
            self.add(source.name(), node.name());
        }
    }

    fn collect(module: Module<'_>, definitions: &Definitions<'_>, options: Options) -> Self {
        let mut imports = Self::new(module.name());
        for identity in &definitions.module_identities {
            imports.add_macro("MODULE-IDENTITY");
            if let Some(reference) = emitted_anchor(
                module,
                definitions,
                options,
                identity.oid(),
                identity.oid_refs(),
            ) {
                imports.add_oid_ref(module, reference);
            }
        }
        for identity in &definitions.oid_assignments {
            if identity.kind() == ModuleIdentityKind::ObjectIdentity {
                imports.add_macro("OBJECT-IDENTITY");
            }
            if let Some(reference) = emitted_anchor(
                module,
                definitions,
                options,
                identity.oid(),
                identity.oid_refs(),
            ) {
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
                && let Some(reference) =
                    emitted_anchor(module, definitions, options, node.oid(), object.oid_refs())
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
        for notification in &definitions.notifications {
            imports.add_macro("NOTIFICATION-TYPE");
            if let Some(node) = notification.node()
                && let Some(reference) = emitted_anchor(
                    module,
                    definitions,
                    options,
                    node.oid(),
                    notification.oid_refs(),
                )
            {
                imports.add_oid_ref(module, reference);
            }
            for object in notification.objects() {
                if let Some(source) = object.module() {
                    imports.add(source.name(), object.name());
                }
            }
        }
        if !options.conformance {
            return imports;
        }
        for group in &definitions.groups {
            imports.add_macro(if group.is_notification_group() {
                "NOTIFICATION-GROUP"
            } else {
                "OBJECT-GROUP"
            });
            if let Some(node) = group.node()
                && let Some(reference) =
                    emitted_anchor(module, definitions, options, node.oid(), group.oid_refs())
            {
                imports.add_oid_ref(module, reference);
            }
            for member in group.members() {
                imports.add_node(member);
            }
        }
        for compliance in &definitions.compliances {
            imports.add_macro("MODULE-COMPLIANCE");
            if let Some(node) = compliance.node()
                && let Some(reference) = emitted_anchor(
                    module,
                    definitions,
                    options,
                    node.oid(),
                    compliance.oid_refs(),
                )
            {
                imports.add_oid_ref(module, reference);
            }
            for clause in compliance.modules() {
                let target = referenced_module(module, &clause.module_name);
                for name in &clause.mandatory_groups {
                    imports.add(target.name(), name);
                }
                for group in &clause.groups {
                    imports.add(target.name(), &group.group);
                }
                for object in &clause.objects {
                    imports.add(target.name(), &object.object);
                    if let Some(syntax) = &object.syntax {
                        imports.add_constraints(module, syntax);
                    }
                    if let Some(syntax) = &object.write_syntax {
                        imports.add_constraints(module, syntax);
                    }
                }
            }
        }
        for capability in &definitions.capabilities {
            imports.add_macro("AGENT-CAPABILITIES");
            if let Some(node) = capability.node()
                && let Some(reference) = emitted_anchor(
                    module,
                    definitions,
                    options,
                    node.oid(),
                    capability.oid_refs(),
                )
            {
                imports.add_oid_ref(module, reference);
            }
            for supports in capability.supports() {
                if let Some(target) = module.mib.module(&supports.module_name) {
                    for name in &supports.includes {
                        imports.add(target.name(), name);
                    }
                    for variation in &supports.object_variations {
                        imports.add(target.name(), &variation.object);
                        for reference in &variation.creation_requires {
                            imports.add_oid_ref(module, reference);
                        }
                        if let Some(syntax) = &variation.syntax {
                            imports.add_constraints(module, syntax);
                        }
                        if let Some(syntax) = &variation.write_syntax {
                            imports.add_constraints(module, syntax);
                        }
                        if let Some(default) = &variation.def_val
                            && matches!(default.value(), DefValValue::Oid(_))
                            && let Some(reference) = default.oid_ref()
                        {
                            imports.add_oid_ref(module, reference);
                        }
                    }
                    for variation in &supports.notification_variations {
                        imports.add(target.name(), &variation.notification);
                    }
                }
            }
        }
        imports
    }
}

fn referenced_module<'a>(module: Module<'a>, name: &str) -> Module<'a> {
    if name.is_empty() {
        module
    } else {
        module
            .mib
            .module(name)
            .expect("validated conformance target module")
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
        let imports = Imports::collect(module, definitions, self.options);

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

        for notification in &definitions.notifications {
            self.blank_line()?;
            self.emit_notification(module, definitions, *notification)?;
        }

        if self.options.conformance {
            for group in &definitions.groups {
                self.blank_line()?;
                self.emit_group(module, definitions, *group)?;
            }
            for compliance in &definitions.compliances {
                self.blank_line()?;
                self.emit_compliance(module, definitions, *compliance)?;
            }
            for capability in &definitions.capabilities {
                self.blank_line()?;
                self.emit_capability(module, definitions, *capability)?;
            }
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
            format_args!(
                "::= {}",
                oid_assignment(module, definitions, self.options, identity)
            ),
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
            format_args!(
                "::= {}",
                oid_assignment(module, definitions, self.options, identity)
            ),
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
                oid_assignment(module, definitions, self.options, identity)
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
            format_args!("MAX-ACCESS {}", canonical_object_access(object.access())),
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
            self.line(1, format_args!("DEFVAL {{ {} }}", defval_syntax(default)))?;
        }
        let oid = object.node().expect("validated object node").oid();
        self.line(
            1,
            format_args!(
                "::= {}",
                object_oid_assignment(module, definitions, self.options, object, oid)
            ),
        )
    }

    fn emit_notification(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        notification: Notification<'_>,
    ) -> io::Result<()> {
        self.line(0, format_args!("{} NOTIFICATION-TYPE", notification.name()))?;
        let objects = notification
            .objects()
            .map(|object| object.name())
            .collect::<Vec<_>>();
        self.name_list(1, "OBJECTS", &objects)?;
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(Some(notification.status()))),
        )?;
        self.description_clause(1, notification.description(), false)?;
        if !notification.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", notification.reference())?;
        }
        self.entity_oid_assignment(
            module,
            definitions,
            notification.node(),
            notification.oid_refs(),
        )
    }

    fn emit_group(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        group: Group<'_>,
    ) -> io::Result<()> {
        let (macro_name, members_keyword) = if group.is_notification_group() {
            ("NOTIFICATION-GROUP", "NOTIFICATIONS")
        } else {
            ("OBJECT-GROUP", "OBJECTS")
        };
        self.line(0, format_args!("{} {macro_name}", group.name()))?;
        let members = group
            .members()
            .map(|member| member.name())
            .collect::<Vec<_>>();
        self.required_name_list(1, members_keyword, &members)?;
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(Some(group.status()))),
        )?;
        self.description_clause(1, group.description(), false)?;
        if !group.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", group.reference())?;
        }
        self.entity_oid_assignment(module, definitions, group.node(), group.oid_refs())
    }

    fn emit_compliance(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        compliance: Compliance<'_>,
    ) -> io::Result<()> {
        self.line(0, format_args!("{} MODULE-COMPLIANCE", compliance.name()))?;
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(Some(compliance.status()))),
        )?;
        self.description_clause(1, compliance.description(), false)?;
        if !compliance.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", compliance.reference())?;
        }
        for clause in compliance.modules() {
            if clause.module_name.is_empty() {
                self.line(1, format_args!("MODULE"))?;
            } else {
                self.line(1, format_args!("MODULE {}", clause.module_name))?;
            }
            self.name_list(2, "MANDATORY-GROUPS", &clause.mandatory_groups)?;
            for group in &clause.groups {
                self.line(2, format_args!("GROUP {}", group.group))?;
                self.description_clause(2, &group.description, false)?;
            }
            for object in &clause.objects {
                self.line(2, format_args!("OBJECT {}", object.object))?;
                if let Some(syntax) = &object.syntax {
                    self.line(
                        3,
                        format_args!("SYNTAX {}", syntax_constraints(module, syntax)),
                    )?;
                }
                if let Some(syntax) = &object.write_syntax {
                    self.line(
                        3,
                        format_args!("WRITE-SYNTAX {}", syntax_constraints(module, syntax)),
                    )?;
                }
                if let Some(access) = object.min_access {
                    self.line(3, format_args!("MIN-ACCESS {}", canonical_access(access)))?;
                }
                self.description_clause(3, &object.description, false)?;
            }
        }
        self.entity_oid_assignment(
            module,
            definitions,
            compliance.node(),
            compliance.oid_refs(),
        )
    }

    fn emit_capability(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        capability: Capability<'_>,
    ) -> io::Result<()> {
        self.line(0, format_args!("{} AGENT-CAPABILITIES", capability.name()))?;
        self.quoted_clause(1, "PRODUCT-RELEASE", capability.product_release())?;
        self.line(
            1,
            format_args!("STATUS {}", canonical_status(Some(capability.status()))),
        )?;
        self.description_clause(1, capability.description(), false)?;
        if !capability.reference().is_empty() {
            self.quoted_clause(1, "REFERENCE", capability.reference())?;
        }
        for supports in capability.supports() {
            self.line(1, format_args!("SUPPORTS {}", supports.module_name))?;
            self.required_name_list(2, "INCLUDES", &supports.includes)?;
            for variation in &supports.object_variations {
                self.line(2, format_args!("VARIATION {}", variation.object))?;
                if let Some(syntax) = &variation.syntax {
                    self.line(
                        3,
                        format_args!("SYNTAX {}", syntax_constraints(module, syntax)),
                    )?;
                }
                if let Some(syntax) = &variation.write_syntax {
                    self.line(
                        3,
                        format_args!("WRITE-SYNTAX {}", syntax_constraints(module, syntax)),
                    )?;
                }
                if let Some(access) = variation.access {
                    self.line(3, format_args!("ACCESS {}", canonical_access(access)))?;
                }
                let creation_requires = variation
                    .creation_requires
                    .iter()
                    .map(|reference| reference.name.as_str())
                    .collect::<Vec<_>>();
                self.name_list(3, "CREATION-REQUIRES", &creation_requires)?;
                if let Some(default) = &variation.def_val {
                    self.line(3, format_args!("DEFVAL {{ {} }}", defval_syntax(default)))?;
                }
                self.description_clause(3, &variation.description, false)?;
            }
            for variation in &supports.notification_variations {
                self.line(2, format_args!("VARIATION {}", variation.notification))?;
                if let Some(access) = variation.access {
                    self.line(3, format_args!("ACCESS {}", canonical_access(access)))?;
                }
                self.description_clause(3, &variation.description, false)?;
            }
        }
        self.entity_oid_assignment(
            module,
            definitions,
            capability.node(),
            capability.oid_refs(),
        )
    }

    fn entity_oid_assignment(
        &mut self,
        module: Module<'_>,
        definitions: &Definitions<'_>,
        node: Option<crate::mib::Node<'_>>,
        references: &[OidRef],
    ) -> io::Result<()> {
        let node = node.expect("validated entity OID");
        self.line(
            1,
            format_args!(
                "::= {}",
                oid_assignment_from_refs(module, definitions, self.options, node.oid(), references,)
            ),
        )
    }

    fn name_list<T: AsRef<str>>(
        &mut self,
        indent: usize,
        keyword: &str,
        names: &[T],
    ) -> io::Result<()> {
        if names.is_empty() {
            return Ok(());
        }
        let names = names
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<_>>()
            .join(", ");
        self.line(indent, format_args!("{keyword} {{ {names} }}"))
    }

    fn required_name_list<T: AsRef<str>>(
        &mut self,
        indent: usize,
        keyword: &str,
        names: &[T],
    ) -> io::Result<()> {
        if names.is_empty() {
            self.line(indent, format_args!("{keyword} {{ }}"))
        } else {
            self.name_list(indent, keyword, names)
        }
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
        Access::ReadWrite => "read-write",
        Access::WriteOnly => "write-only",
        Access::ReadCreate => "read-create",
        Access::NotImplemented => "not-implemented",
    }
}

fn canonical_object_access(access: Access) -> &'static str {
    if access == Access::WriteOnly {
        "read-write"
    } else {
        canonical_access(access)
    }
}

fn oid_assignment(
    module: Module<'_>,
    definitions: &Definitions<'_>,
    options: Options,
    identity: &ModuleIdentityData,
) -> String {
    oid_assignment_from_refs(
        module,
        definitions,
        options,
        identity.oid(),
        identity.oid_refs(),
    )
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

fn emitted_anchor<'a>(
    module: Module<'_>,
    definitions: &Definitions<'_>,
    options: Options,
    oid: &Oid,
    references: &'a [OidRef],
) -> Option<&'a OidRef> {
    references
        .iter()
        .filter(|reference| {
            reference
                .oid()
                .is_some_and(|anchor| oid.starts_with(anchor))
                && reference.module_id().is_some_and(|source| {
                    source != module.id() || definitions.emits_oid_name(&reference.name, options)
                })
        })
        .max_by_key(|reference| reference.oid().map_or(0, |oid| oid.len()))
}

fn oid_assignment_from_refs(
    module: Module<'_>,
    definitions: &Definitions<'_>,
    options: Options,
    oid: &Oid,
    references: &[OidRef],
) -> String {
    if let Some(reference) = emitted_anchor(module, definitions, options, oid, references) {
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
    module: Module<'_>,
    definitions: &Definitions<'_>,
    options: Options,
    object: Object<'_>,
    oid: &Oid,
) -> String {
    oid_assignment_from_refs(module, definitions, options, oid, object.oid_refs())
}

fn syntax_constraints(module: Module<'_>, syntax: &SyntaxConstraints) -> String {
    let typ = syntax.type_id.map(|type_id| module.mib.type_by_id(type_id));
    let prefix = if !syntax.bits.is_empty() {
        format!("BITS {}", format_named_values(&syntax.bits))
    } else if !syntax.enums.is_empty() {
        let name = typ
            .filter(|typ| !typ.name().is_empty() && !is_builtin_type_name(typ.name()))
            .map_or("INTEGER", canonical_type_name);
        format!("{name} {}", format_named_values(&syntax.enums))
    } else {
        typ.map_or_else(
            || "INTEGER".to_owned(),
            |typ| {
                if typ.name().is_empty() {
                    base_type_syntax(typ.effective_base()).to_owned()
                } else {
                    canonical_type_name(typ).to_owned()
                }
            },
        )
    };
    let sizes = if syntax.declared_sizes.is_empty() {
        &syntax.sizes
    } else {
        &syntax.declared_sizes
    };
    let ranges = if syntax.declared_ranges.is_empty() {
        &syntax.ranges
    } else {
        &syntax.declared_ranges
    };
    constrained_syntax(&prefix, ranges, sizes)
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

fn defval_syntax(default: &crate::mib::DefVal) -> String {
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

fn validate_syntax_constraints(
    module: Module<'_>,
    definition: &str,
    syntax: &SyntaxConstraints,
) -> Result<(), Error> {
    let type_id = syntax
        .type_id
        .ok_or_else(|| unsupported(definition, "contains an unresolved refinement type"))?;
    let typ = module.mib.type_by_id(type_id);
    validate_base(definition, typ.effective_base())?;
    validate_ranges(definition, &syntax.declared_ranges)?;
    validate_ranges(definition, &syntax.declared_sizes)?;
    validate_ranges(definition, &syntax.ranges)?;
    validate_ranges(definition, &syntax.sizes)?;
    if syntax.ranges_constrained && syntax.declared_ranges.is_empty() && syntax.ranges.is_empty() {
        return Err(unsupported(
            definition,
            "contains an empty refinement range intersection",
        ));
    }
    if syntax.sizes_constrained && syntax.declared_sizes.is_empty() && syntax.sizes.is_empty() {
        return Err(unsupported(
            definition,
            "contains an empty refinement size intersection",
        ));
    }
    Ok(())
}

fn validate_oid_default(
    definition: &str,
    default: Option<&crate::mib::DefVal>,
) -> Result<(), Error> {
    let Some(default) = default else {
        return Ok(());
    };
    if let DefValValue::Oid(oid) = default.value()
        && (!default.oid_ref().is_some_and(|reference| {
            reference.oid() == Some(oid) && reference.module_id().is_some()
        }) || oid.is_empty())
    {
        return Err(unsupported(
            definition,
            "contains a variation OID DEFVAL without a symbolic anchor",
        ));
    }
    if matches!(default.value(), DefValValue::Bytes(_)) && !valid_byte_defval(default.raw()) {
        return Err(unsupported(
            definition,
            "contains a malformed variation byte-string DEFVAL",
        ));
    }
    Ok(())
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

    #[test]
    fn creation_requires_provenance_keeps_the_selected_module_version() {
        let inputs: [(&str, &[u8]); 6] = [
            (
                "embedded:SNMPv2-SMI",
                crate::lower::base_modules::embedded_content("SNMPv2-SMI").unwrap(),
            ),
            (
                "embedded:SNMPv2-CONF",
                crate::lower::base_modules::embedded_content("SNMPv2-CONF").unwrap(),
            ),
            (
                "target",
                br#"CREATION-TARGET-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
creationTargetRoot OBJECT IDENTIFIER ::= { enterprises 424301 }
creationTargetTable OBJECT-TYPE SYNTAX SEQUENCE OF CreationTargetEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Table." ::= { creationTargetRoot 1 }
creationTargetEntry OBJECT-TYPE SYNTAX CreationTargetEntry MAX-ACCESS not-accessible STATUS current DESCRIPTION "Row." INDEX { creationTargetIndex } ::= { creationTargetTable 1 }
creationTargetIndex OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-only STATUS current DESCRIPTION "Index." ::= { creationTargetEntry 1 }
CreationTargetEntry ::= SEQUENCE { creationTargetIndex Integer32 }
END
"#,
            ),
            (
                "first",
                br#"DUPLICATE-CREATION-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
aCreation OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-create STATUS current DESCRIPTION "First." ::= { enterprises 424302 }
END
"#,
            ),
            (
                "second",
                br#"DUPLICATE-CREATION-MIB DEFINITIONS ::= BEGIN
IMPORTS OBJECT-TYPE, Integer32, enterprises FROM SNMPv2-SMI;
bCreation OBJECT-TYPE SYNTAX Integer32 MAX-ACCESS read-create STATUS current DESCRIPTION "Second." ::= { enterprises 424303 }
END
"#,
            ),
            (
                "consumer",
                br#"VERSION-CREATION-CONSUMER-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM SNMPv2-SMI AGENT-CAPABILITIES FROM SNMPv2-CONF bCreation FROM DUPLICATE-CREATION-MIB;
versionCreationCapabilities AGENT-CAPABILITIES
    PRODUCT-RELEASE "test"
    STATUS current
    DESCRIPTION "Version."
    SUPPORTS CREATION-TARGET-MIB
        INCLUDES { }
        VARIATION creationTargetEntry
            CREATION-REQUIRES { bCreation }
            DESCRIPTION "Row."
    ::= { enterprises 424304 }
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
        let consumer = mib.module("VERSION-CREATION-CONSUMER-MIB").unwrap();
        let selected = consumer.import_source("bCreation").unwrap();
        let capability = consumer.capability("versionCreationCapabilities").unwrap();
        let reference = &capability.supports()[0].object_variations[0].creation_requires[0];
        assert_eq!(reference.module_id(), Some(selected.id()));
        assert!(selected.object("bCreation").is_some());

        let mut first = Vec::new();
        write(&mut first, &mib, "VERSION-CREATION-CONSUMER-MIB").unwrap();
        let mut second = Vec::new();
        write(&mut second, &mib, "VERSION-CREATION-CONSUMER-MIB").unwrap();
        assert_eq!(first, second);
        let output = String::from_utf8(first).unwrap();
        assert!(output.contains("bCreation\n        FROM DUPLICATE-CREATION-MIB"));
        assert!(output.contains("CREATION-REQUIRES { bCreation }"));
    }
}
