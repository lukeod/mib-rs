//! Structured, resolver-domain-specific symbol resolution explanations.

use std::fmt;

use crate::mib::{ImportResolution, Mib, ModuleId, Oid, Symbol, UnresolvedRef};
use crate::types::{ResolutionDomain, ResolverStrictness};

/// The kind of a candidate definition in a resolution trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResolutionCandidateKind {
    /// An `OBJECT-TYPE` definition.
    Object,
    /// A `NOTIFICATION-TYPE` or `TRAP-TYPE` definition.
    Notification,
    /// An `OBJECT-GROUP` or `NOTIFICATION-GROUP` definition.
    Group,
    /// A `MODULE-COMPLIANCE` definition.
    Compliance,
    /// An `AGENT-CAPABILITIES` definition.
    Capability,
    /// A type assignment or `TEXTUAL-CONVENTION` definition.
    Type,
    /// An OID assignment without a more specific semantic definition.
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
    /// Identifies the exact loaded module version that defines the symbol.
    pub module: ModuleId,
    /// Names the module that defines the symbol.
    pub module_name: String,
    /// Identifies the module source when the loader assigned a label.
    pub source_label: Option<String>,
    /// Contains the module's `LAST-UPDATED` value, or an empty string when absent.
    pub last_updated: String,
    /// Classifies the definition.
    pub kind: ResolutionCandidateKind,
    /// Identifies the definition in the resolved MIB arenas.
    pub symbol: Symbol,
    /// Contains the definition's numeric OID when it has a resolved OID node.
    pub oid: Option<Oid>,
    /// Whether this definition kind can satisfy the selected domain.
    pub applicable: bool,
}

/// Exact loaded module version used as a resolution scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionScope {
    /// Identifies the exact loaded module version used as the scope.
    pub module: ModuleId,
    /// Names the scoped module.
    pub module_name: String,
    /// Identifies the scoped module's source when the loader assigned a label.
    pub source_label: Option<String>,
    /// Contains the module's `LAST-UPDATED` value, or an empty string when absent.
    pub last_updated: String,
}

/// Resolver fallback tiers applicable to this domain, strictness, and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolutionFallbackPolicy {
    /// Indicates whether this name has an intrinsic foundation-module rule.
    pub intrinsic: bool,
    /// Indicates whether the domain and strictness enable foundation-module fallback.
    pub constrained: bool,
    /// Indicates whether the domain and strictness enable global fallback.
    pub global: bool,
}

/// Strategy that selected the final definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionStrategy {
    /// Selected a definition in the scoped module.
    Local,
    /// Followed an import directly to its declared source module.
    DirectImport,
    /// Followed an import re-exported through one or more modules.
    ForwardedImport,
    /// Followed the resolved portion of a partially resolved import clause.
    PartialImport,
    /// Followed a compatibility alias for the imported module name.
    AliasImport,
    /// Selected a definition from an intrinsic foundation module.
    IntrinsicFallback,
    /// Selected a definition from a strictness-dependent foundation module.
    ConstrainedFallback,
    /// Selected a definition through global fallback.
    GlobalFallback,
    /// Selected the only applicable candidate during an unscoped lookup.
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

/// Final classification of a traced lookup.
///
/// [`ResolutionTrace::target`] is present exactly when the outcome is
/// [`Resolved`](Self::Resolved). An unscoped lookup is ambiguous when multiple
/// applicable candidates exist. Scoped lookups report an unresolved lookup as
/// [`Missing`](Self::Missing), even when other modules define the same name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionOutcome {
    /// The lookup selected one target.
    Resolved,
    /// An unscoped lookup found multiple applicable candidates.
    Ambiguous,
    /// The applicable resolver rules did not select a target.
    Missing,
}

/// Definition selected by a traced lookup and the strategy that selected it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionTarget {
    /// Describes the selected loaded definition.
    pub candidate: ResolutionCandidate,
    /// Identifies the resolver strategy that selected the definition.
    pub strategy: ResolutionStrategy,
}

/// Structured explanation of one domain-specific name lookup.
#[derive(Debug, Clone)]
pub struct ResolutionTrace {
    /// Preserves the original query exactly as supplied by the caller.
    pub query: String,
    /// Contains the unqualified symbol name extracted from `query`.
    pub symbol: String,
    /// Identifies the resolver domain whose definition rules were applied.
    pub domain: ResolutionDomain,
    /// Contains the exact module scope, or `None` for an unscoped lookup.
    pub scope: Option<ResolutionScope>,
    /// Records the resolver strictness active on the MIB.
    pub strictness: ResolverStrictness,
    /// Describes the fallback tiers enabled for this domain, strictness, and name.
    pub fallbacks: ResolutionFallbackPolicy,
    /// Every cross-kind definition with this name, deterministically ordered.
    pub candidates: Vec<ResolutionCandidate>,
    /// Exact pre-collapse import provenance for the scope, when it imports the name.
    pub import: Option<ImportResolution>,
    /// Classifies the final lookup result.
    pub outcome: ResolutionOutcome,
    /// Contains the selected definition exactly when `outcome` is resolved.
    pub target: Option<ResolutionTarget>,
    /// Lists unresolved references with the traced symbol name across loaded modules.
    ///
    /// The list is diagnostic provenance and does not determine `outcome`.
    pub unresolved: Vec<UnresolvedRef>,
}

/// Failure to parse a trace query or select an exact module scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolutionTraceError {
    /// The query contains no characters.
    #[error("symbol query is empty")]
    EmptyQuery,
    /// The qualified query does not have exactly one nonempty `module::symbol` pair.
    #[error("invalid qualified symbol query: {0}")]
    InvalidQualifiedQuery(String),
    /// The qualified query and explicit scope name different modules.
    #[error("qualified query scope {query_scope:?} conflicts with --module {explicit_scope:?}")]
    ConflictingScope {
        /// Names the module in the qualified query.
        query_scope: String,
        /// Names the separately supplied module scope.
        explicit_scope: String,
    },
    /// No loaded module has the requested scope name.
    #[error("module scope not found: {0}")]
    ModuleNotFound(String),
    /// Multiple loaded module versions have the requested scope name.
    #[error("module scope {module:?} is ambiguous across loaded sources: {candidates:?}")]
    AmbiguousModuleScope {
        /// Names the requested module.
        module: String,
        /// Lists every exact loaded module version with the requested name.
        candidates: Vec<ResolutionScope>,
    },
}

impl Mib {
    /// Explains a symbol lookup using the exact rules for `domain`.
    ///
    /// Use `module::symbol` in `query` to establish module scope, or pass
    /// `module_scope` with an unqualified query. If both forms provide the same
    /// module name, the lookup uses that scope. If they disagree, the method
    /// returns [`ResolutionTraceError::ConflictingScope`]. A module name must
    /// identify exactly one loaded version; duplicate versions return
    /// [`ResolutionTraceError::AmbiguousModuleScope`] with every candidate.
    ///
    /// A scoped lookup follows the same local, import, and fallback rules as
    /// semantic resolution for `domain`. An unscoped lookup does not infer
    /// imports or fallbacks: it resolves only when exactly one loaded definition
    /// has the requested name and an applicable kind. Multiple applicable
    /// definitions produce [`ResolutionOutcome::Ambiguous`], and no applicable
    /// definition produces [`ResolutionOutcome::Missing`].
    ///
    /// On success, [`ResolutionTrace::target`] is present exactly when
    /// [`ResolutionTrace::outcome`] is [`ResolutionOutcome::Resolved`].
    /// Candidate and unresolved-reference lists use deterministic ordering.
    ///
    /// # Examples
    ///
    /// ```
    /// use mib_rs::load::Loader;
    /// use mib_rs::mib::{ResolutionOutcome, ResolutionStrategy};
    /// use mib_rs::source::memory;
    /// use mib_rs::types::ResolutionDomain;
    ///
    /// let source = memory(
    ///     "TRACE-EXAMPLE-MIB",
    ///     b"TRACE-EXAMPLE-MIB DEFINITIONS ::= BEGIN\n\
    ///       traceRoot OBJECT IDENTIFIER ::= { iso 424300 }\n\
    ///       END\n",
    /// );
    /// let mib = Loader::new()
    ///     .source(source)
    ///     .modules(["TRACE-EXAMPLE-MIB"])
    ///     .load()?;
    /// let trace = mib.trace_symbol(
    ///     "TRACE-EXAMPLE-MIB::traceRoot",
    ///     None,
    ///     ResolutionDomain::Oid,
    /// )?;
    ///
    /// assert_eq!(trace.outcome, ResolutionOutcome::Resolved);
    /// assert_eq!(trace.target.unwrap().strategy, ResolutionStrategy::Local);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
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
