//! Resolver context: mutable state shared across all resolver phases.
//!
//! [`ResolverContext`] holds the in-progress [`Mib`], parsed IR modules,
//! various lookup indexes, and unresolved reference tracking. Registration
//! owns initial population of the module list; later phases read and mutate
//! the shared context.

use std::collections::{HashMap, HashSet};

use crate::ir;
use crate::source::{SourceRange, SourceSet};
use crate::types::{DiagCode, Diagnostic, DiagnosticConfig, Language, ResolverStrictness};

use super::super::mib::Mib;
use super::super::types::*;

/// Reason an imported or referenced symbol could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnresolvedReason {
    /// The source module was not found in the loaded module set.
    ModuleNotFound,
    /// The source module exists but does not export the requested symbol.
    SymbolNotExported,
    /// A type reference could not be resolved.
    TypeNotFound,
    /// A dependency cycle prevented resolution.
    DependencyCycle,
    /// An OID component's named parent could not be found.
    ComponentNotFound,
    /// A TRAP-TYPE's ENTERPRISE reference could not be resolved.
    EnterpriseNotFound,
    /// Incrementing a generic TRAP-TYPE number would overflow its OID arc.
    TrapNumberOverflow,
    /// An AUGMENTS target row object could not be found.
    AugmentsTargetNotFound,
    /// An INDEX object reference could not be resolved.
    IndexObjectNotFound,
    /// A generic object reference could not be resolved.
    ObjectNotFound,
}

impl UnresolvedReason {
    /// Convert to the public-facing reason string used in [`UnresolvedRef`].
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleNotFound => "module_not_found",
            Self::SymbolNotExported => "symbol_not_exported",
            Self::TypeNotFound => "unknown_type",
            Self::DependencyCycle => "dependency_cycle",
            Self::ComponentNotFound => "unknown_parent",
            Self::EnterpriseNotFound => "unknown_parent",
            Self::TrapNumberOverflow => "trap_number_overflow",
            Self::AugmentsTargetNotFound => "unknown_parent",
            Self::IndexObjectNotFound => "unknown_index_object",
            Self::ObjectNotFound => "unknown_object",
        }
    }
}

/// Resolver-internal module identifier.
///
/// A lightweight index into [`ResolverContext::modules`]. Distinct from
/// [`ModuleId`], which identifies resolved modules in the output [`Mib`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct IrModuleId(pub u32);

impl IrModuleId {
    /// Return the index into the modules Vec.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// Mutable state shared across all resolver phases.
///
/// Created once at the start of resolution and passed through each phase.
/// After resolution completes, [`ResolverContext::drop_modules`] releases
/// the IR data and [`ResolverContext::finalize_unresolved`] converts
/// internal tracking entries into the public [`UnresolvedRef`] type.
pub(super) struct ResolverContext {
    /// The output Mib being constructed.
    pub mib: Mib,

    /// Parsed modules (base + user), ordered. Dropped after resolution.
    pub modules: Vec<ir::Module>,

    /// Module name -> list of IR module indices (multiple versions possible).
    pub module_index: HashMap<String, Vec<IrModuleId>>,

    /// IR module -> resolved module.
    pub module_to_resolved: HashMap<IrModuleId, ModuleId>,
    /// Resolved module -> IR module.
    pub resolved_to_module: HashMap<ModuleId, IrModuleId>,

    /// IR module -> symbol name -> NodeId. Populated by OID phase.
    pub module_symbol_to_node: HashMap<IrModuleId, HashMap<String, NodeId>>,

    /// IR module -> symbol name -> source IR module. Import chain.
    pub module_imports: HashMap<IrModuleId, HashMap<String, IrModuleId>>,

    /// IR module -> symbol name -> TypeId. Populated by type phase.
    pub module_symbol_to_type: HashMap<IrModuleId, HashMap<String, TypeId>>,

    /// IR module -> set of all definition names.
    pub module_def_names: HashMap<IrModuleId, HashSet<String>>,

    /// IR module -> set of definitions with OID assignments.
    pub module_oid_def_names: HashMap<IrModuleId, HashSet<String>>,

    /// Cached base module references.
    pub snmpv2_smi: Option<IrModuleId>,
    pub rfc1155_smi: Option<IrModuleId>,
    pub snmpv2_tc: Option<IrModuleId>,

    /// Tracks which imported symbols are actually used.
    pub used_imports: HashMap<IrModuleId, HashSet<String>>,

    /// Unresolved reference tracking.
    pub unresolved_imports: Vec<UnresolvedTracking>,
    pub unresolved_types: Vec<UnresolvedTracking>,
    pub unresolved_oids: Vec<UnresolvedTracking>,
    pub unresolved_indexes: Vec<UnresolvedTracking>,
    pub unresolved_notif_objects: Vec<UnresolvedTracking>,

    /// Resolver strictness controls fallback behavior.
    pub strictness: ResolverStrictness,

    /// Diagnostic configuration controls reporting only.
    pub diag_config: DiagnosticConfig,
}

/// Tracks an unresolved reference during resolution, before conversion to the
/// public [`UnresolvedRef`] type.
pub(super) struct UnresolvedTracking {
    /// Category of the unresolved reference (import, type, OID, etc.).
    pub kind: UnresolvedKind,
    /// Name of the symbol that could not be resolved.
    pub symbol: String,
    /// Module where the unresolved reference originated.
    pub module: String,
    /// Why the reference could not be resolved.
    pub reason: UnresolvedReason,
}

impl ResolverContext {
    /// Create a new resolver context with no registered modules.
    pub fn new(
        strictness: ResolverStrictness,
        diag_config: DiagnosticConfig,
        sources: SourceSet,
    ) -> Self {
        Self {
            mib: Mib::with_sources(sources),
            modules: Vec::new(),
            module_index: HashMap::new(),
            module_to_resolved: HashMap::new(),
            resolved_to_module: HashMap::new(),
            module_symbol_to_node: HashMap::new(),
            module_imports: HashMap::new(),
            module_symbol_to_type: HashMap::new(),
            module_def_names: HashMap::new(),
            module_oid_def_names: HashMap::new(),
            snmpv2_smi: None,
            rfc1155_smi: None,
            snmpv2_tc: None,
            used_imports: HashMap::new(),
            unresolved_imports: Vec::new(),
            unresolved_types: Vec::new(),
            unresolved_oids: Vec::new(),
            unresolved_indexes: Vec::new(),
            unresolved_notif_objects: Vec::new(),
            strictness,
            diag_config,
        }
    }

    /// Iterate all modules as (IrModuleId, &Module) pairs.
    pub fn all_modules(&self) -> impl Iterator<Item = (IrModuleId, &ir::Module)> {
        self.modules
            .iter()
            .enumerate()
            .map(|(idx, m)| (IrModuleId(idx as u32), m))
    }

    /// Iterate user (non-base) modules as (IrModuleId, &Module) pairs.
    pub fn user_modules(&self) -> impl Iterator<Item = (IrModuleId, &ir::Module)> {
        self.all_modules()
            .filter(|(_, m)| !crate::lower::base_modules::is_base_module(&m.name))
    }

    /// Collect `(module_index, definition_index)` pairs for definitions matching a predicate.
    ///
    /// Useful for gathering work items before mutating the context, since
    /// iteration and mutation cannot happen simultaneously.
    pub fn collect_definitions(&self, filter: fn(&ir::Definition) -> bool) -> Vec<(usize, usize)> {
        (0..self.modules.len())
            .flat_map(|idx| {
                self.modules[idx]
                    .definitions
                    .iter()
                    .enumerate()
                    .filter_map(
                        move |(di, def)| {
                            if filter(def) { Some((idx, di)) } else { None }
                        },
                    )
            })
            .collect()
    }

    /// Emit a diagnostic if the config says to report it.
    ///
    /// Diagnostics filtered out by the [`DiagnosticConfig`] are silently
    /// dropped. Source ranges are retained exactly for later presentation.
    pub fn emit_diagnostic(
        &mut self,
        code: DiagCode,
        ir_mod: Option<IrModuleId>,
        range: Option<SourceRange>,
        message: String,
    ) {
        if !self.diag_config.should_collect(code) {
            return;
        }
        let severity = self.diag_config.effective_severity(code);
        let module_name = ir_mod.map(|id| self.modules[id.index()].name.clone());
        self.mib.add_diagnostic(Diagnostic {
            severity,
            code,
            message,
            module: module_name.filter(|s| !s.is_empty()),
            range,
        });
    }

    /// Mark an imported symbol as used.
    pub fn mark_import_used(&mut self, ir_mod: IrModuleId, name: &str) {
        self.used_imports
            .entry(ir_mod)
            .or_default()
            .insert(name.to_string());
    }

    /// Look up a node by name within a module's scope (local defs, then imports).
    ///
    /// Returns `(NodeId, used_import)` where `used_import` is true if the
    /// symbol was found through the module's import chain rather than locally.
    pub fn lookup_node_for_module(&self, mod_id: IrModuleId, name: &str) -> Option<(NodeId, bool)> {
        // Check module's own symbols
        if let Some(node) = self
            .module_symbol_to_node
            .get(&mod_id)
            .and_then(|syms| syms.get(name))
        {
            return Some((*node, false));
        }
        // Check imports (single hop, already transitively resolved)
        if let Some(source) = self
            .module_imports
            .get(&mod_id)
            .and_then(|imps| imps.get(name))
            && let Some(node) = self
                .module_symbol_to_node
                .get(source)
                .and_then(|syms| syms.get(name))
        {
            return Some((*node, true));
        }
        None
    }

    /// Retain symbolic OID references with the exact module version selected
    /// by module scope, import resolution, or foundation fallback.
    pub fn build_oid_refs(&self, mod_id: IrModuleId, oid: &ir::OidAssignment) -> Vec<OidRef> {
        self.build_oid_component_refs(mod_id, &oid.components)
    }

    pub fn build_oid_component_refs(
        &self,
        mod_id: IrModuleId,
        components: &[ir::OidComponent],
    ) -> Vec<OidRef> {
        components
            .iter()
            .filter_map(|component| {
                let (name, range, target) = match component {
                    ir::OidComponent::Name { name, range }
                    | ir::OidComponent::NamedNumber { name, range, .. } => {
                        (name, *range, self.oid_ref_target(mod_id, name))
                    }
                    ir::OidComponent::QualifiedName {
                        module,
                        name,
                        range,
                    }
                    | ir::OidComponent::QualifiedNamedNumber {
                        module,
                        name,
                        range,
                        ..
                    } => (
                        name,
                        *range,
                        self.module_index.get(module).and_then(|versions| {
                            versions.iter().copied().find(|version| {
                                self.module_symbol_to_node
                                    .get(version)
                                    .is_some_and(|symbols| symbols.contains_key(name))
                            })
                        }),
                    ),
                    ir::OidComponent::Number { .. } => return None,
                };
                let node = target.and_then(|target| {
                    self.module_symbol_to_node
                        .get(&target)
                        .and_then(|symbols| symbols.get(name))
                        .copied()
                });
                Some(OidRef {
                    name: name.clone(),
                    range,
                    module: target.and_then(|target| self.module_to_resolved.get(&target).copied()),
                    oid: node.map(|node| self.mib.tree().oid_of(node).clone()),
                })
            })
            .collect()
    }

    pub fn oid_ref_for_name(&self, mod_id: IrModuleId, name: &str, range: SourceRange) -> OidRef {
        let target = self.oid_ref_target(mod_id, name);
        let node = target.and_then(|target| {
            self.module_symbol_to_node
                .get(&target)
                .and_then(|symbols| symbols.get(name))
                .copied()
        });
        OidRef {
            name: name.to_owned(),
            range,
            module: target.and_then(|target| self.module_to_resolved.get(&target).copied()),
            oid: node.map(|node| self.mib.tree().oid_of(node).clone()),
        }
    }

    fn oid_ref_target(&self, mod_id: IrModuleId, name: &str) -> Option<IrModuleId> {
        if self
            .module_symbol_to_node
            .get(&mod_id)
            .is_some_and(|symbols| symbols.contains_key(name))
        {
            return Some(mod_id);
        }
        if let Some(target) = self
            .module_imports
            .get(&mod_id)
            .and_then(|imports| imports.get(name))
            .copied()
        {
            return Some(target);
        }
        if matches!(name, "iso" | "ccitt" | "joint-iso-ccitt") {
            return self.snmpv2_smi;
        }
        if self.strictness.allow_constrained_fallbacks() {
            return [self.snmpv2_smi, self.rfc1155_smi]
                .into_iter()
                .flatten()
                .find(|target| {
                    self.module_symbol_to_node
                        .get(target)
                        .is_some_and(|symbols| symbols.contains_key(name))
                });
        }
        None
    }

    /// Look up an object by name within a module's scope (local defs, then imports).
    ///
    /// Returns `(ObjectId, used_import)` where `used_import` is true if the
    /// symbol was found through the module's import chain.
    pub fn lookup_object_for_module(
        &self,
        mod_id: IrModuleId,
        name: &str,
    ) -> Option<(ObjectId, bool)> {
        if let Some(&resolved_mod) = self.module_to_resolved.get(&mod_id)
            && let Some(obj_id) = self.mib.raw().module(resolved_mod).object_by_name(name)
        {
            return Some((obj_id, false));
        }

        if let Some(&source_ir) = self
            .module_imports
            .get(&mod_id)
            .and_then(|imps| imps.get(name))
            && let Some(&source_resolved) = self.module_to_resolved.get(&source_ir)
            && let Some(obj_id) = self.mib.raw().module(source_resolved).object_by_name(name)
        {
            return Some((obj_id, true));
        }

        None
    }

    /// Look up a type by name within a module's scope, with well-known fallbacks.
    ///
    /// Search order:
    /// - Local definitions in the module.
    /// - Imported symbols (single hop, already transitively resolved).
    /// - Tier 1 fallback (always): ASN.1 primitives from SNMPv2-SMI.
    /// - Tier 2 fallback (Normal+ strictness): SMI globals, SMIv1 types, SNMPv2-TC types.
    ///
    /// Returns `(TypeId, used_import)` where `used_import` is true if the
    /// symbol was found through the module's import chain.
    pub fn lookup_type_for_module(&self, mod_id: IrModuleId, name: &str) -> Option<(TypeId, bool)> {
        if let Some(result) = self.lookup_type_in_module_scope(mod_id, name) {
            return Some(result);
        }
        self.try_well_known_type_fallbacks(name)
            .map(|id| (id, false))
    }

    fn lookup_type_in_module_scope(
        &self,
        mod_id: IrModuleId,
        name: &str,
    ) -> Option<(TypeId, bool)> {
        // Local
        if let Some(t) = self
            .module_symbol_to_type
            .get(&mod_id)
            .and_then(|syms| syms.get(name))
        {
            return Some((*t, false));
        }
        // Imports
        if let Some(source) = self
            .module_imports
            .get(&mod_id)
            .and_then(|imps| imps.get(name))
            && let Some(t) = self
                .module_symbol_to_type
                .get(source)
                .and_then(|syms| syms.get(name))
        {
            return Some((*t, true));
        }
        None
    }

    /// Try well-known type fallbacks.
    /// Tier 1 (always): ASN.1 primitives.
    /// Tier 2 (constrained, Normal+): SMI globals, SMIv1, SNMPv2-TC.
    /// Tier 3 (global, Permissive only): not handled here (see global lookup).
    fn try_well_known_type_fallbacks(&self, name: &str) -> Option<TypeId> {
        // Tier 1: ASN.1 primitives always resolve from SNMPv2-SMI
        if matches!(
            name,
            "INTEGER" | "OCTET STRING" | "OBJECT IDENTIFIER" | "BITS"
        ) && let Some(smi) = self.snmpv2_smi
        {
            return self
                .module_symbol_to_type
                .get(&smi)
                .and_then(|syms| syms.get(name))
                .copied();
        }
        // Tier 2: constrained fallbacks (Normal+)
        if !self.strictness.allow_constrained_fallbacks() {
            return None;
        }
        // SMI global types from SNMPv2-SMI
        if let Some(smi) = self.snmpv2_smi
            && let Some(t) = self
                .module_symbol_to_type
                .get(&smi)
                .and_then(|syms| syms.get(name))
        {
            return Some(*t);
        }
        // SMIv1 types from RFC1155-SMI
        if let Some(rfc) = self.rfc1155_smi
            && let Some(t) = self
                .module_symbol_to_type
                .get(&rfc)
                .and_then(|syms| syms.get(name))
        {
            return Some(*t);
        }
        // TC types from SNMPv2-TC
        if let Some(tc) = self.snmpv2_tc
            && let Some(t) = self
                .module_symbol_to_type
                .get(&tc)
                .and_then(|syms| syms.get(name))
        {
            return Some(*t);
        }
        None
    }

    /// Global node lookup across all modules.
    pub fn lookup_node_global(&self, name: &str) -> Option<NodeId> {
        for (id, _) in self.all_modules() {
            if let Some(node) = self
                .module_symbol_to_node
                .get(&id)
                .and_then(|syms| syms.get(name))
            {
                return Some(*node);
            }
        }
        None
    }

    /// Look up a node by name across all versions of a named module.
    ///
    /// Checks every IR module registered under `module_name` (there may be
    /// multiple versions) and returns the first match.
    pub fn lookup_node_in_module(&self, module_name: &str, name: &str) -> Option<NodeId> {
        let candidates = self.module_index.get(module_name)?;
        for &cand in candidates {
            if let Some(node) = self
                .module_symbol_to_node
                .get(&cand)
                .and_then(|syms| syms.get(name))
            {
                return Some(*node);
            }
        }
        None
    }

    /// Get the language of an IR module.
    pub fn module_language(&self, id: IrModuleId) -> Language {
        self.modules[id.index()].language
    }

    /// Extract LAST-UPDATED from an IR module's first ModuleIdentity def.
    pub fn extract_last_updated(&self, id: IrModuleId) -> String {
        let m = &self.modules[id.index()];
        for def in &m.definitions {
            if let ir::Definition::ModuleIdentity(mi) = def {
                return mi.last_updated.clone();
            }
        }
        String::new()
    }

    /// Record an unresolved reference and emit a diagnostic.
    pub fn record_unresolved_import(
        &mut self,
        symbol: impl Into<String>,
        importing_module: impl Into<String>,
        from_module: impl AsRef<str>,
        reason: UnresolvedReason,
        ir_mod: IrModuleId,
        range: Option<SourceRange>,
    ) {
        let symbol = symbol.into();
        let importing_module = importing_module.into();
        let code = if reason == UnresolvedReason::ModuleNotFound {
            DiagCode::ImportModuleNotFound
        } else {
            DiagCode::ImportNotFound
        };
        self.unresolved_imports.push(UnresolvedTracking {
            kind: UnresolvedKind::Import,
            symbol: symbol.clone(),
            module: importing_module,
            reason,
        });
        self.emit_diagnostic(
            code,
            Some(ir_mod),
            range,
            format!(
                "unresolved import: {:?} from {:?} ({})",
                symbol,
                from_module.as_ref(),
                reason.as_str()
            ),
        );
    }

    /// Record an unresolved type reference and emit a diagnostic.
    pub fn record_unresolved_type(
        &mut self,
        referrer: impl AsRef<str>,
        symbol: impl Into<String>,
        module: impl Into<String>,
        reason: UnresolvedReason,
        ir_mod: IrModuleId,
        range: SourceRange,
    ) {
        debug_assert!(matches!(
            reason,
            UnresolvedReason::TypeNotFound | UnresolvedReason::DependencyCycle
        ));
        let symbol = symbol.into();
        let module = module.into();
        self.unresolved_types.push(UnresolvedTracking {
            kind: UnresolvedKind::Type,
            symbol: symbol.clone(),
            module,
            reason,
        });
        let (code, message) = if reason == UnresolvedReason::DependencyCycle {
            (
                DiagCode::TypeCycle,
                format!(
                    "type cycle: {:?} references {:?} in a dependency cycle",
                    referrer.as_ref(),
                    symbol
                ),
            )
        } else {
            (
                DiagCode::TypeUnknown,
                format!(
                    "unresolved type: {:?} references unknown type {:?}",
                    referrer.as_ref(),
                    symbol
                ),
            )
        };
        self.emit_diagnostic(code, Some(ir_mod), Some(range), message);
    }

    /// Record an unresolved OID component and emit a diagnostic.
    pub fn record_unresolved_oid(
        &mut self,
        def_name: impl AsRef<str>,
        component: impl Into<String>,
        module: impl Into<String>,
        reason: UnresolvedReason,
        ir_mod: IrModuleId,
        range: SourceRange,
    ) {
        let component = component.into();
        let module = module.into();
        self.unresolved_oids.push(UnresolvedTracking {
            kind: UnresolvedKind::Oid,
            symbol: component.clone(),
            module,
            reason,
        });
        let code = if reason == UnresolvedReason::DependencyCycle {
            DiagCode::OidRecursive
        } else {
            DiagCode::OidOrphan
        };
        self.emit_diagnostic(
            code,
            Some(ir_mod),
            Some(range),
            format!(
                "unresolved OID: {:?} references unknown parent {:?}",
                def_name.as_ref(),
                component
            ),
        );
    }

    /// Record a TRAP-TYPE number that cannot be represented in its derived OID.
    pub fn record_trap_number_overflow(
        &mut self,
        def_name: impl Into<String>,
        module: impl Into<String>,
        ir_mod: IrModuleId,
        range: SourceRange,
    ) {
        let def_name = def_name.into();
        self.unresolved_oids.push(UnresolvedTracking {
            kind: UnresolvedKind::Oid,
            symbol: def_name.clone(),
            module: module.into(),
            reason: UnresolvedReason::TrapNumberOverflow,
        });
        self.emit_diagnostic(
            DiagCode::TrapNumberOverflow,
            Some(ir_mod),
            Some(range),
            format!(
                "TRAP-TYPE {:?} trap number overflows the snmpTraps sub-identifier",
                def_name
            ),
        );
    }

    /// Record an unresolved INDEX object reference and emit a diagnostic.
    pub fn record_unresolved_index(
        &mut self,
        row: impl AsRef<str>,
        index_object: impl Into<String>,
        module: impl Into<String>,
        ir_mod: IrModuleId,
        range: SourceRange,
    ) {
        let index_object = index_object.into();
        let module = module.into();
        self.unresolved_indexes.push(UnresolvedTracking {
            kind: UnresolvedKind::Index,
            symbol: index_object.clone(),
            module,
            reason: UnresolvedReason::IndexObjectNotFound,
        });
        self.emit_diagnostic(
            DiagCode::IndexUnresolved,
            Some(ir_mod),
            Some(range),
            format!(
                "unresolved INDEX: {:?} references unknown object {:?}",
                row.as_ref(),
                index_object
            ),
        );
    }

    /// Record an unresolved NOTIFICATION-TYPE OBJECTS reference and emit a diagnostic.
    pub fn record_unresolved_notification_object(
        &mut self,
        notification: impl AsRef<str>,
        object: impl Into<String>,
        module: impl Into<String>,
        ir_mod: IrModuleId,
        range: SourceRange,
    ) {
        let object = object.into();
        let module = module.into();
        self.unresolved_notif_objects.push(UnresolvedTracking {
            kind: UnresolvedKind::NotificationObject,
            symbol: object.clone(),
            module,
            reason: UnresolvedReason::ObjectNotFound,
        });
        self.emit_diagnostic(
            DiagCode::ObjectsUnresolved,
            Some(ir_mod),
            Some(range),
            format!(
                "unresolved OBJECTS: {:?} references unknown object {:?}",
                notification.as_ref(),
                object
            ),
        );
    }

    /// Drop parsed IR modules and associated indexes to free memory.
    pub fn drop_modules(&mut self) {
        self.modules.clear();
        self.module_index.clear();
        self.module_def_names.clear();
        self.module_oid_def_names.clear();
    }

    /// Convert internal [`UnresolvedTracking`] entries to the public [`UnresolvedRef`] type.
    pub fn finalize_unresolved(&mut self) {
        let all = self
            .unresolved_imports
            .drain(..)
            .chain(self.unresolved_types.drain(..))
            .chain(self.unresolved_oids.drain(..))
            .chain(self.unresolved_indexes.drain(..))
            .chain(self.unresolved_notif_objects.drain(..));

        for u in all {
            self.mib.add_unresolved(UnresolvedRef {
                kind: u.kind,
                symbol: u.symbol,
                module: u.module,
                reason: u.reason.as_str().to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::source::{ByteOffset, SourceOrigin, SourceRangeError};

    use super::*;

    fn insert_source(sources: &mut SourceSet, identity: &str, bytes: &[u8]) -> crate::SourceId {
        sources
            .insert(SourceOrigin::memory(identity), identity, Arc::from(bytes))
            .unwrap()
    }

    fn context(sources: SourceSet) -> ResolverContext {
        ResolverContext::new(
            ResolverStrictness::Strict,
            DiagnosticConfig::default(),
            sources,
        )
    }

    fn emit_test_diagnostic(ctx: &mut ResolverContext, range: Option<SourceRange>) {
        ctx.emit_diagnostic(
            DiagCode::TypeUnknown,
            None,
            range,
            "test diagnostic".to_string(),
        );
    }

    #[test]
    fn diagnostic_uses_validated_retained_source_range() {
        let mut sources = SourceSet::new();
        let source_id = insert_source(&mut sources, "valid", b"first\nsecond");
        let range = sources.get(source_id).unwrap().range(8..10).unwrap();
        let mut ctx = context(sources);

        emit_test_diagnostic(&mut ctx, Some(range));

        let diagnostic = &ctx.mib.diagnostics()[0];
        assert_eq!(diagnostic.range, Some(range));
        let report = ctx.mib.diagnostic_report();
        assert_eq!(report.get(0).unwrap().slice().unwrap(), Some(&b"co"[..]));
    }

    #[test]
    fn diagnostic_without_source_range_has_no_location() {
        let mut ctx = context(SourceSet::new());

        emit_test_diagnostic(&mut ctx, None);

        let diagnostic = &ctx.mib.diagnostics()[0];
        assert_eq!(diagnostic.range, None);
    }

    #[test]
    fn diagnostic_preserves_unretained_range_for_checked_report_failure() {
        let mut retained_sources = SourceSet::new();
        insert_source(&mut retained_sources, "retained", b"retained");

        let mut foreign_sources = SourceSet::new();
        insert_source(&mut foreign_sources, "foreign-first", b"first");
        let foreign_id = insert_source(&mut foreign_sources, "foreign-second", b"second");
        let foreign_range = foreign_sources
            .get(foreign_id)
            .unwrap()
            .range(0..1)
            .unwrap();
        let mut ctx = context(retained_sources);

        emit_test_diagnostic(&mut ctx, Some(foreign_range));

        let diagnostic = &ctx.mib.diagnostics()[0];
        assert_eq!(diagnostic.range, Some(foreign_range));
        let report = ctx.mib.diagnostic_report();
        assert!(matches!(
            report.get(0).unwrap().range(),
            Err(crate::DiagnosticReportError::SourceNotRetained(id)) if id == foreign_id
        ));
    }

    #[test]
    fn out_of_bounds_diagnostic_range_cannot_be_safely_constructed() {
        let mut sources = SourceSet::new();
        let source_id = insert_source(&mut sources, "short", b"abc");
        let source = sources.get(source_id).unwrap();

        assert_eq!(
            source.range(0..4),
            Err(SourceRangeError::OffsetOutOfBounds {
                offset: ByteOffset::new(4),
                len: ByteOffset::new(3),
            })
        );
    }
}
