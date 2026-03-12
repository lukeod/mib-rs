use std::collections::{HashMap, HashSet};

use crate::ir;
use crate::types::{DiagCode, Diagnostic, DiagnosticConfig, Language, ResolverStrictness, Span};

use super::super::mib::Mib;
use super::super::types::*;

/// Reason an imported or referenced symbol could not be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UnresolvedReason {
    ModuleNotFound,
    SymbolNotExported,
    TypeNotFound,
    DependencyCycle,
    ComponentNotFound,
    EnterpriseNotFound,
    AugmentsTargetNotFound,
    IndexObjectNotFound,
    ObjectNotFound,
}

impl UnresolvedReason {
    /// Convert to the public-facing reason string used in UnresolvedRef.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleNotFound => "module_not_found",
            Self::SymbolNotExported => "symbol_not_exported",
            Self::TypeNotFound => "unknown_type",
            Self::DependencyCycle => "dependency_cycle",
            Self::ComponentNotFound => "unknown_parent",
            Self::EnterpriseNotFound => "unknown_parent",
            Self::AugmentsTargetNotFound => "unknown_parent",
            Self::IndexObjectNotFound => "unknown_index_object",
            Self::ObjectNotFound => "unknown_object",
        }
    }
}

/// Resolver-internal module index (index into ctx.modules Vec).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct IrModuleId(pub u32);

impl IrModuleId {
    /// Return the index into the modules Vec.
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// All mutable state for the five resolver phases.
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

/// Tracks an unresolved reference during resolution.
pub(super) struct UnresolvedTracking {
    pub kind: UnresolvedKind,
    pub symbol: String,
    pub module: String,
    pub reason: UnresolvedReason,
}

impl ResolverContext {
    pub fn new(
        modules: Vec<ir::Module>,
        strictness: ResolverStrictness,
        diag_config: DiagnosticConfig,
    ) -> Self {
        Self {
            mib: Mib::new(),
            modules,
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

    /// Emit a diagnostic if the config says to report it.
    pub fn emit_diagnostic(
        &mut self,
        code: DiagCode,
        ir_mod: Option<IrModuleId>,
        span: Span,
        message: String,
    ) {
        let severity = code.severity();
        if !self.diag_config.should_report(code) {
            return;
        }
        let (module_name, line, col) = match ir_mod {
            Some(id) => {
                let m = &self.modules[id.index()];
                let (l, c) = line_col_from_module(m, span);
                (m.name.clone(), l, c)
            }
            None => (String::new(), 0, 0),
        };
        self.mib.add_diagnostic(Diagnostic {
            severity,
            code,
            message,
            module: Some(module_name).filter(|s| !s.is_empty()),
            line: if line > 0 { Some(line) } else { None },
            column: if col > 0 { Some(col) } else { None },
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

    /// Look up an object by name within a module's scope (local defs, then imports).
    pub fn lookup_object_for_module(
        &self,
        mod_id: IrModuleId,
        name: &str,
    ) -> Option<(ObjectId, bool)> {
        if let Some(&resolved_mod) = self.module_to_resolved.get(&mod_id)
            && let Some(obj_id) = self.mib.module(resolved_mod).object_by_name(name)
        {
            return Some((obj_id, false));
        }

        if let Some(&source_ir) = self
            .module_imports
            .get(&mod_id)
            .and_then(|imps| imps.get(name))
            && let Some(&source_resolved) = self.module_to_resolved.get(&source_ir)
            && let Some(obj_id) = self.mib.module(source_resolved).object_by_name(name)
        {
            return Some((obj_id, true));
        }

        None
    }

    /// Look up a type by name within a module's scope, with well-known fallbacks.
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

    /// Look up a node across all versions of a named module.
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
        symbol: &str,
        importing_module: &str,
        from_module: &str,
        reason: UnresolvedReason,
        ir_mod: IrModuleId,
        span: Span,
    ) {
        let code = if reason == UnresolvedReason::ModuleNotFound {
            DiagCode::ImportModuleNotFound
        } else {
            DiagCode::ImportNotFound
        };
        self.unresolved_imports.push(UnresolvedTracking {
            kind: UnresolvedKind::Import,
            symbol: symbol.to_string(),
            module: importing_module.to_string(),
            reason,
        });
        self.emit_diagnostic(
            code,
            Some(ir_mod),
            span,
            format!("unresolved import: {:?} from {:?} ({})", symbol, from_module, reason.as_str()),
        );
    }

    pub fn record_unresolved_type(
        &mut self,
        referrer: &str,
        symbol: &str,
        module: &str,
        ir_mod: IrModuleId,
        span: Span,
    ) {
        self.unresolved_types.push(UnresolvedTracking {
            kind: UnresolvedKind::Type,
            symbol: symbol.to_string(),
            module: module.to_string(),
            reason: UnresolvedReason::TypeNotFound,
        });
        self.emit_diagnostic(
            DiagCode::TypeUnknown,
            Some(ir_mod),
            span,
            format!("unresolved type: {:?} references unknown type {:?}", referrer, symbol),
        );
    }

    pub fn record_unresolved_oid(
        &mut self,
        def_name: &str,
        component: &str,
        module: &str,
        reason: UnresolvedReason,
        ir_mod: IrModuleId,
        span: Span,
    ) {
        self.unresolved_oids.push(UnresolvedTracking {
            kind: UnresolvedKind::Oid,
            symbol: component.to_string(),
            module: module.to_string(),
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
            span,
            format!("unresolved OID: {:?} references unknown parent {:?}", def_name, component),
        );
    }

    pub fn record_unresolved_index(
        &mut self,
        row: &str,
        index_object: &str,
        module: &str,
        ir_mod: IrModuleId,
        span: Span,
    ) {
        self.unresolved_indexes.push(UnresolvedTracking {
            kind: UnresolvedKind::Index,
            symbol: index_object.to_string(),
            module: module.to_string(),
            reason: UnresolvedReason::IndexObjectNotFound,
        });
        self.emit_diagnostic(
            DiagCode::IndexUnresolved,
            Some(ir_mod),
            span,
            format!("unresolved INDEX: {:?} references unknown object {:?}", row, index_object),
        );
    }

    pub fn record_unresolved_notification_object(
        &mut self,
        notification: &str,
        object: &str,
        module: &str,
        ir_mod: IrModuleId,
        span: Span,
    ) {
        self.unresolved_notif_objects.push(UnresolvedTracking {
            kind: UnresolvedKind::NotificationObject,
            symbol: object.to_string(),
            module: module.to_string(),
            reason: UnresolvedReason::ObjectNotFound,
        });
        self.emit_diagnostic(
            DiagCode::ObjectsUnresolved,
            Some(ir_mod),
            span,
            format!("unresolved OBJECTS: {:?} references unknown object {:?}", notification, object),
        );
    }

    /// Drop parsed modules after resolution to free memory.
    pub fn drop_modules(&mut self) {
        self.modules.clear();
        self.module_index.clear();
        self.module_def_names.clear();
        self.module_oid_def_names.clear();
    }

    /// Convert unresolved tracking entries to the public UnresolvedRef type.
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

fn line_col_from_module(m: &ir::Module, span: Span) -> (usize, usize) {
    if span.is_synthetic() || m.line_table.is_empty() {
        return (0, 0);
    }
    crate::types::line_col_from_table(&m.line_table, span.start)
}
