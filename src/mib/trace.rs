//! Structured, resolver-domain-specific symbol resolution explanations.

use std::fmt;

use crate::mib::{ImportResolution, Mib, ModuleId, Oid, Symbol, UnresolvedRef};
use crate::types::{ResolutionDomain, ResolverStrictness};

/// The kind of a candidate definition in a resolution trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolutionCandidateKind {
    Object,
    Notification,
    Group,
    Compliance,
    Capability,
    Type,
    Node,
}

impl From<Symbol> for ResolutionCandidateKind {
    fn from(symbol: Symbol) -> Self {
        match symbol {
            Symbol::Object(_) => Self::Object,
            Symbol::Notification(_) => Self::Notification,
            Symbol::Group(_) => Self::Group,
            Symbol::Compliance(_) => Self::Compliance,
            Symbol::Capability(_) => Self::Capability,
            Symbol::Type(_) => Self::Type,
            Symbol::Node(_) => Self::Node,
        }
    }
}

impl fmt::Display for ResolutionCandidateKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Object => "object",
            Self::Notification => "notification",
            Self::Group => "group",
            Self::Compliance => "compliance",
            Self::Capability => "capability",
            Self::Type => "type",
            Self::Node => "node",
        })
    }
}

/// One loaded definition with the traced name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionCandidate {
    pub module: ModuleId,
    pub module_name: String,
    pub source_label: Option<String>,
    pub last_updated: String,
    pub kind: ResolutionCandidateKind,
    pub symbol: Symbol,
    pub oid: Option<Oid>,
    /// Whether this definition kind can satisfy the selected domain.
    pub applicable: bool,
}

/// Exact loaded module version used as a resolution scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionScope {
    pub module: ModuleId,
    pub module_name: String,
    pub source_label: Option<String>,
    pub last_updated: String,
}

/// Resolver fallback tiers applicable to this domain, strictness, and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionFallbackPolicy {
    pub intrinsic: bool,
    pub constrained: bool,
    pub global: bool,
}

/// Strategy that selected the final definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    Local,
    DirectImport,
    ForwardedImport,
    PartialImport,
    AliasImport,
    IntrinsicFallback,
    ConstrainedFallback,
    GlobalFallback,
    UniqueCandidate,
}

impl fmt::Display for ResolutionStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Local => "local definition",
            Self::DirectImport => "direct import",
            Self::ForwardedImport => "forwarded import",
            Self::PartialImport => "partial import",
            Self::AliasImport => "import alias",
            Self::IntrinsicFallback => "intrinsic fallback",
            Self::ConstrainedFallback => "constrained fallback",
            Self::GlobalFallback => "global fallback",
            Self::UniqueCandidate => "unique unscoped candidate",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionOutcome {
    Resolved,
    Ambiguous,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionTarget {
    pub candidate: ResolutionCandidate,
    pub strategy: ResolutionStrategy,
}

/// Structured explanation of one domain-specific name lookup.
#[derive(Debug, Clone)]
pub struct ResolutionTrace {
    pub query: String,
    pub symbol: String,
    pub domain: ResolutionDomain,
    pub scope: Option<ResolutionScope>,
    pub strictness: ResolverStrictness,
    pub fallbacks: ResolutionFallbackPolicy,
    /// Every cross-kind definition with this name, deterministically ordered.
    pub candidates: Vec<ResolutionCandidate>,
    /// Exact pre-collapse import provenance for the scope, when it imports the name.
    pub import: Option<ImportResolution>,
    pub outcome: ResolutionOutcome,
    pub target: Option<ResolutionTarget>,
    pub unresolved: Vec<UnresolvedRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionTraceError {
    #[error("symbol query is empty")]
    EmptyQuery,
    #[error("invalid qualified symbol query: {0}")]
    InvalidQualifiedQuery(String),
    #[error("qualified query scope {query_scope:?} conflicts with --module {explicit_scope:?}")]
    ConflictingScope {
        query_scope: String,
        explicit_scope: String,
    },
    #[error("module scope not found: {0}")]
    ModuleNotFound(String),
    #[error("module scope {module:?} is ambiguous across loaded sources: {candidates:?}")]
    AmbiguousModuleScope {
        module: String,
        candidates: Vec<ResolutionScope>,
    },
}

impl Mib {
    /// Explain a symbol lookup using the exact rules for `domain`.
    ///
    /// A qualified query establishes module scope. An explicit scope may be
    /// supplied for an unqualified query. A duplicated same-name module scope
    /// is rejected with all exact source candidates rather than silently
    /// selecting a version.
    pub fn trace_symbol(
        &self,
        query: &str,
        module_scope: Option<&str>,
        domain: ResolutionDomain,
    ) -> Result<ResolutionTrace, ResolutionTraceError> {
        let (qualified_scope, symbol_name) = parse_query(query)?;
        let scope_name = match (qualified_scope, module_scope) {
            (Some(query_scope), Some(explicit_scope)) if query_scope != explicit_scope => {
                return Err(ResolutionTraceError::ConflictingScope {
                    query_scope: query_scope.to_owned(),
                    explicit_scope: explicit_scope.to_owned(),
                });
            }
            (Some(query_scope), _) => Some(query_scope),
            (None, Some(explicit_scope)) => Some(explicit_scope),
            (None, None) => None,
        };
        let scope = scope_name
            .map(|name| self.unique_resolution_scope(name))
            .transpose()?;
        let candidates = self.resolution_candidates(symbol_name, domain);
        let fallback_domain = super::resolver::rules::fallback_domain(domain, symbol_name);
        let fallbacks = ResolutionFallbackPolicy {
            intrinsic: super::resolver::rules::intrinsic_foundation_module(
                fallback_domain,
                symbol_name,
            )
            .is_some(),
            constrained: !super::resolver::rules::constrained_foundation_modules(
                fallback_domain,
                self.resolver_strictness(),
            )
            .is_empty(),
            global: super::resolver::rules::allows_global_fallback(
                fallback_domain,
                self.resolver_strictness(),
            ),
        };

        let (target, import) = match &scope {
            Some(scope) => self.resolve_trace_in_scope(scope.module, symbol_name, domain),
            None => {
                let applicable = candidates
                    .iter()
                    .filter(|candidate| candidate.applicable)
                    .collect::<Vec<_>>();
                if applicable.len() == 1 {
                    (
                        Some(ResolutionTarget {
                            candidate: applicable[0].clone(),
                            strategy: ResolutionStrategy::UniqueCandidate,
                        }),
                        None,
                    )
                } else {
                    (None, None)
                }
            }
        };
        let outcome = if target.is_some() {
            ResolutionOutcome::Resolved
        } else if scope.is_none()
            && candidates
                .iter()
                .filter(|candidate| candidate.applicable)
                .count()
                > 1
        {
            ResolutionOutcome::Ambiguous
        } else {
            ResolutionOutcome::Missing
        };

        let mut unresolved = self
            .unresolved()
            .iter()
            .filter(|reference| reference.symbol == symbol_name)
            .cloned()
            .collect::<Vec<_>>();
        unresolved.sort_by(|left, right| {
            left.module
                .cmp(&right.module)
                .then((left.kind as u8).cmp(&(right.kind as u8)))
                .then(left.reason.cmp(&right.reason))
        });

        Ok(ResolutionTrace {
            query: query.to_owned(),
            symbol: symbol_name.to_owned(),
            domain,
            scope,
            strictness: self.resolver_strictness(),
            fallbacks,
            candidates,
            import,
            outcome,
            target,
            unresolved,
        })
    }

    fn unique_resolution_scope(
        &self,
        module_name: &str,
    ) -> Result<ResolutionScope, ResolutionTraceError> {
        let mut scopes = self
            .modules_slice()
            .iter()
            .enumerate()
            .filter(|(_, module)| module.name() == module_name)
            .map(|(index, _)| self.resolution_scope(ModuleId::new(index as u32)))
            .collect::<Vec<_>>();
        scopes.sort_by(|left, right| {
            left.source_label
                .cmp(&right.source_label)
                .then_with(|| right.last_updated.cmp(&left.last_updated))
                .then(left.module.cmp(&right.module))
        });
        match scopes.len() {
            0 => Err(ResolutionTraceError::ModuleNotFound(module_name.to_owned())),
            1 => Ok(scopes.remove(0)),
            _ => Err(ResolutionTraceError::AmbiguousModuleScope {
                module: module_name.to_owned(),
                candidates: scopes,
            }),
        }
    }

    fn resolution_scope(&self, module: ModuleId) -> ResolutionScope {
        let handle = self.module_by_id(module);
        ResolutionScope {
            module,
            module_name: handle.name().to_owned(),
            source_label: handle.source_label().map(str::to_owned),
            last_updated: handle.last_updated().to_owned(),
        }
    }

    fn resolution_candidates(
        &self,
        name: &str,
        domain: ResolutionDomain,
    ) -> Vec<ResolutionCandidate> {
        let mut candidates = self
            .modules_slice()
            .iter()
            .enumerate()
            .flat_map(|(index, module)| {
                module.symbols(name).into_iter().map(move |symbol| {
                    self.resolution_candidate(ModuleId::new(index as u32), symbol, domain, name)
                })
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.module_name
                .cmp(&right.module_name)
                .then(left.source_label.cmp(&right.source_label))
                .then_with(|| right.last_updated.cmp(&left.last_updated))
                .then(left.kind.cmp(&right.kind))
                .then(left.module.cmp(&right.module))
        });
        candidates
    }

    fn resolution_candidate(
        &self,
        module: ModuleId,
        symbol: Symbol,
        domain: ResolutionDomain,
        name: &str,
    ) -> ResolutionCandidate {
        let handle = self.module_by_id(module);
        ResolutionCandidate {
            module,
            module_name: handle.name().to_owned(),
            source_label: handle.source_label().map(str::to_owned),
            last_updated: handle.last_updated().to_owned(),
            kind: symbol.into(),
            symbol,
            oid: symbol
                .node(self)
                .map(|node| self.node_by_id(node).oid().clone()),
            applicable: symbol_matches_domain(symbol, domain, name),
        }
    }

    fn resolve_trace_in_scope(
        &self,
        scope: ModuleId,
        name: &str,
        domain: ResolutionDomain,
    ) -> (Option<ResolutionTarget>, Option<ImportResolution>) {
        let fallback_domain = super::resolver::rules::fallback_domain(domain, name);

        // Symbolic OID roots are recognized before ordinary module scope.
        if domain == ResolutionDomain::Oid
            && let Some(module_name) =
                super::resolver::rules::intrinsic_foundation_module(fallback_domain, name)
            && let Some(target) = self.foundation_candidate(module_name, name, domain)
        {
            let import = self.module_data(scope).import_resolution(name).cloned();
            return (
                Some(ResolutionTarget {
                    candidate: target,
                    strategy: ResolutionStrategy::IntrinsicFallback,
                }),
                import,
            );
        }

        if let Some(local) = self.domain_candidate_in_module(scope, name, domain) {
            return (
                Some(ResolutionTarget {
                    candidate: local,
                    strategy: ResolutionStrategy::Local,
                }),
                None,
            );
        }

        let import = self.module_data(scope).import_resolution(name).cloned();
        if let Some(resolution) = &import
            && let Some(target_module) = resolution.target
            && let Some(imported) = self.domain_candidate_in_module(target_module, name, domain)
        {
            let strategy = match resolution.mode {
                crate::mib::ImportResolutionMode::Direct => ResolutionStrategy::DirectImport,
                crate::mib::ImportResolutionMode::Alias => ResolutionStrategy::AliasImport,
                crate::mib::ImportResolutionMode::Forwarded => ResolutionStrategy::ForwardedImport,
                crate::mib::ImportResolutionMode::Partial => ResolutionStrategy::PartialImport,
                crate::mib::ImportResolutionMode::Unresolved
                | crate::mib::ImportResolutionMode::Cycle => {
                    unreachable!("an unresolved import cannot retain a target")
                }
            };
            return (
                Some(ResolutionTarget {
                    candidate: imported,
                    strategy,
                }),
                import,
            );
        }

        if let Some(module_name) =
            super::resolver::rules::intrinsic_foundation_module(fallback_domain, name)
            && let Some(target) = self.foundation_candidate(module_name, name, domain)
        {
            return (
                Some(ResolutionTarget {
                    candidate: target,
                    strategy: ResolutionStrategy::IntrinsicFallback,
                }),
                import,
            );
        }
        for &module_name in super::resolver::rules::constrained_foundation_modules(
            fallback_domain,
            self.resolver_strictness(),
        ) {
            if let Some(target) = self.foundation_candidate(module_name, name, domain) {
                return (
                    Some(ResolutionTarget {
                        candidate: target,
                        strategy: ResolutionStrategy::ConstrainedFallback,
                    }),
                    import,
                );
            }
        }
        if super::resolver::rules::allows_global_fallback(
            fallback_domain,
            self.resolver_strictness(),
        ) && let Some(target) = self.global_domain_candidate(name, domain)
        {
            return (
                Some(ResolutionTarget {
                    candidate: target,
                    strategy: ResolutionStrategy::GlobalFallback,
                }),
                import,
            );
        }
        (None, import)
    }

    fn domain_candidate_in_module(
        &self,
        module: ModuleId,
        name: &str,
        domain: ResolutionDomain,
    ) -> Option<ResolutionCandidate> {
        let data = self.module_data(module);
        let symbol = match domain {
            ResolutionDomain::Type => Symbol::Type(data.type_by_name(name)?),
            ResolutionDomain::Oid
            | ResolutionDomain::GroupMember
            | ResolutionDomain::Conformance => data
                .symbols(name)
                .into_iter()
                .find(|symbol| !matches!(symbol, Symbol::Type(_)))?,
            ResolutionDomain::Object | ResolutionDomain::NotificationObject => {
                Symbol::Object(data.object_by_name(name)?)
            }
            ResolutionDomain::Index if super::resolver::rules::is_bare_index_type(name) => {
                Symbol::Type(data.type_by_name(name)?)
            }
            ResolutionDomain::Index => Symbol::Object(data.object_by_name(name)?),
        };
        Some(self.resolution_candidate(module, symbol, domain, name))
    }

    fn foundation_candidate(
        &self,
        module_name: &str,
        name: &str,
        domain: ResolutionDomain,
    ) -> Option<ResolutionCandidate> {
        let module = self
            .modules_slice()
            .iter()
            .enumerate()
            .rev()
            .find(|(_, module)| module.name() == module_name)
            .map(|(index, _)| ModuleId::new(index as u32))?;
        self.domain_candidate_in_module(module, name, domain)
    }

    fn global_domain_candidate(
        &self,
        name: &str,
        domain: ResolutionDomain,
    ) -> Option<ResolutionCandidate> {
        match domain {
            ResolutionDomain::Object | ResolutionDomain::Index => {
                if domain == ResolutionDomain::Index
                    && super::resolver::rules::is_bare_index_type(name)
                {
                    return None;
                }
                let symbol = Symbol::Object(self.object_by_name(name)?);
                let module = symbol.module(self)?;
                Some(self.resolution_candidate(module, symbol, domain, name))
            }
            ResolutionDomain::GroupMember | ResolutionDomain::Conformance => {
                for (index, module) in self.modules_slice().iter().enumerate() {
                    if module.node_by_name(name).is_none() {
                        continue;
                    }
                    return self.domain_candidate_in_module(
                        ModuleId::new(index as u32),
                        name,
                        domain,
                    );
                }
                None
            }
            ResolutionDomain::NotificationObject => {
                for (index, module) in self.modules_slice().iter().enumerate() {
                    let Some(node) = module.node_by_name(name) else {
                        continue;
                    };
                    let symbol = self.symbol_for_resolved_node(node);
                    if !matches!(symbol, Symbol::Object(_)) {
                        return None;
                    }
                    let module = symbol.module(self).unwrap_or(ModuleId::new(index as u32));
                    return Some(self.resolution_candidate(module, symbol, domain, name));
                }
                None
            }
            ResolutionDomain::Type | ResolutionDomain::Oid => None,
        }
    }

    fn symbol_for_resolved_node(&self, node: crate::mib::NodeId) -> Symbol {
        let data = self.node_data(node);
        if let Some(object) = data.object {
            Symbol::Object(object)
        } else if let Some(notification) = data.notification {
            Symbol::Notification(notification)
        } else if let Some(group) = data.group {
            Symbol::Group(group)
        } else if let Some(compliance) = data.compliance {
            Symbol::Compliance(compliance)
        } else if let Some(capability) = data.capability {
            Symbol::Capability(capability)
        } else {
            Symbol::Node(node)
        }
    }
}

fn symbol_matches_domain(symbol: Symbol, domain: ResolutionDomain, name: &str) -> bool {
    match domain {
        ResolutionDomain::Type => matches!(symbol, Symbol::Type(_)),
        ResolutionDomain::Object | ResolutionDomain::NotificationObject => {
            matches!(symbol, Symbol::Object(_))
        }
        ResolutionDomain::Index if super::resolver::rules::is_bare_index_type(name) => {
            matches!(symbol, Symbol::Type(_))
        }
        ResolutionDomain::Index => matches!(symbol, Symbol::Object(_)),
        ResolutionDomain::Oid | ResolutionDomain::GroupMember | ResolutionDomain::Conformance => {
            !matches!(symbol, Symbol::Type(_))
        }
    }
}

fn parse_query(query: &str) -> Result<(Option<&str>, &str), ResolutionTraceError> {
    if query.is_empty() {
        return Err(ResolutionTraceError::EmptyQuery);
    }
    let Some((module, symbol)) = query.split_once("::") else {
        return Ok((None, query));
    };
    if module.is_empty() || symbol.is_empty() || symbol.contains("::") {
        return Err(ResolutionTraceError::InvalidQualifiedQuery(
            query.to_owned(),
        ));
    }
    Ok((Some(module), symbol))
}
