use mib_rs::load::Loader;
use mib_rs::mib::{
    ImportAttemptOutcome, ImportResolutionMode, ImportResolutionStage, ResolutionCandidateKind,
    ResolutionOutcome, ResolutionStrategy,
};
use mib_rs::source::memory_modules;
use mib_rs::types::{DiagnosticConfig, ResolutionDomain, ResolverStrictness};

const MODULES: [(&str, &[u8]); 19] = [
    (
        "TRACE-DEFINER-MIB",
        b"TRACE-DEFINER-MIB DEFINITIONS ::= BEGIN\ntraceRoot OBJECT IDENTIFIER ::= { iso 424285 }\ntraceSymbol OBJECT IDENTIFIER ::= { traceRoot 1 }\ndirectSymbol OBJECT IDENTIFIER ::= { traceRoot 2 }\nEND\n",
    ),
    (
        "TRACE-FORWARDER-MIB",
        b"TRACE-FORWARDER-MIB DEFINITIONS ::= BEGIN\nIMPORTS traceSymbol FROM TRACE-DEFINER-MIB;\nEND\n",
    ),
    (
        "TRACE-SCOPE-MIB",
        b"TRACE-SCOPE-MIB DEFINITIONS ::= BEGIN\nIMPORTS traceSymbol FROM TRACE-FORWARDER-MIB\n        directSymbol FROM TRACE-DEFINER-MIB;\nscopeRoot OBJECT IDENTIFIER ::= { iso 424286 }\nuseTrace OBJECT IDENTIFIER ::= { traceSymbol 1 }\nmissingUse OBJECT IDENTIFIER ::= { missingSymbol 1 }\nglobalObject OBJECT IDENTIFIER ::= { scopeRoot 98 }\nInteger32 OBJECT IDENTIFIER ::= { scopeRoot 99 }\nEND\n",
    ),
    (
        "TRACE-PARTIAL-SOURCE-MIB",
        b"TRACE-PARTIAL-SOURCE-MIB DEFINITIONS ::= BEGIN\npartialRoot OBJECT IDENTIFIER ::= { iso 424287 }\npartialGood OBJECT IDENTIFIER ::= { partialRoot 1 }\nEND\n",
    ),
    (
        "TRACE-PARTIAL-USER-MIB",
        b"TRACE-PARTIAL-USER-MIB DEFINITIONS ::= BEGIN\nIMPORTS partialGood, partialMissing FROM TRACE-PARTIAL-SOURCE-MIB;\npartialUse OBJECT IDENTIFIER ::= { partialGood 1 }\nmissingPartialUse OBJECT IDENTIFIER ::= { partialMissing 1 }\nEND\n",
    ),
    (
        "TRACE-CYCLE-A-MIB",
        b"TRACE-CYCLE-A-MIB DEFINITIONS ::= BEGIN\nIMPORTS cyclicSymbol FROM TRACE-CYCLE-B-MIB;\nEND\n",
    ),
    (
        "TRACE-CYCLE-B-MIB",
        b"TRACE-CYCLE-B-MIB DEFINITIONS ::= BEGIN\nIMPORTS cyclicSymbol FROM TRACE-CYCLE-A-MIB;\nEND\n",
    ),
    (
        "TRACE-MISSING-MIB",
        b"TRACE-MISSING-MIB DEFINITIONS ::= BEGIN\nIMPORTS nowhereSymbol FROM TRACE-ABSENT-MIB;\nEND\n",
    ),
    (
        "TRACE-ALPHA-MIB",
        b"TRACE-ALPHA-MIB DEFINITIONS ::= BEGIN\nambiguousTrace OBJECT IDENTIFIER ::= { iso 424288 }\nEND\n",
    ),
    (
        "TRACE-ZETA-MIB",
        b"TRACE-ZETA-MIB DEFINITIONS ::= BEGIN\nambiguousTrace OBJECT IDENTIFIER ::= { iso 424289 }\nEND\n",
    ),
    (
        "GLOBAL-MIB",
        b"GLOBAL-MIB DEFINITIONS ::= BEGIN\nglobalRoot OBJECT IDENTIFIER ::= { iso 424292 }\nglobalObject OBJECT-TYPE\n    SYNTAX INTEGER\n    ACCESS read-only\n    STATUS mandatory\n    ::= { globalRoot 1 }\nEND\n",
    ),
    (
        "TRACE-OID-SHADOW-MIB",
        b"TRACE-OID-SHADOW-MIB DEFINITIONS ::= BEGIN\niso OBJECT IDENTIFIER ::= { ccitt 424290 }\nEND\n",
    ),
    (
        "TRACE-LOCAL-OID-SHADOW-MIB",
        b"TRACE-LOCAL-OID-SHADOW-MIB DEFINITIONS ::= BEGIN\niso OBJECT IDENTIFIER ::= { ccitt 424291 }\nshadowUse OBJECT IDENTIFIER ::= { iso 1 }\nEND\n",
    ),
    (
        "TRACE-IMPORTED-OID-SHADOW-MIB",
        b"TRACE-IMPORTED-OID-SHADOW-MIB DEFINITIONS ::= BEGIN\nIMPORTS iso FROM TRACE-OID-SHADOW-MIB;\nshadowUse OBJECT IDENTIFIER ::= { iso 2 }\nEND\n",
    ),
    (
        "RFC1213-MIB",
        b"RFC1213-MIB DEFINITIONS ::= BEGIN\naliasSymbol OBJECT IDENTIFIER ::= { iso 424293 }\nEND\n",
    ),
    (
        "TRACE-ALIAS-USER-MIB",
        b"TRACE-ALIAS-USER-MIB DEFINITIONS ::= BEGIN\nIMPORTS aliasSymbol FROM RFC-1213;\naliasUse OBJECT IDENTIFIER ::= { aliasSymbol 1 }\nEND\n",
    ),
    (
        "TRACE-COLLISION-A-OLD-MIB",
        br#"TRACE-COLLISION-A-OLD-MIB DEFINITIONS ::= BEGIN
oldIdentity MODULE-IDENTITY
    LAST-UPDATED "200001010000Z"
    ORGANIZATION "Old"
    CONTACT-INFO "Old"
    DESCRIPTION "Old."
    ::= { iso 424294 }
sharedCollision OBJECT IDENTIFIER ::= { iso 424295 }
END
"#,
    ),
    (
        "TRACE-COLLISION-Z-NEW-MIB",
        br#"TRACE-COLLISION-Z-NEW-MIB DEFINITIONS ::= BEGIN
newIdentity MODULE-IDENTITY
    LAST-UPDATED "202608180000Z"
    ORGANIZATION "New"
    CONTACT-INFO "New"
    DESCRIPTION "New."
    ::= { iso 424296 }
sharedCollision OBJECT-TYPE
    SYNTAX INTEGER
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "New shared object."
    ::= { iso 424295 }
END
"#,
    ),
    (
        "TRACE-COLLISION-IMPORTER-MIB",
        b"TRACE-COLLISION-IMPORTER-MIB DEFINITIONS ::= BEGIN\nIMPORTS sharedCollision FROM TRACE-COLLISION-A-OLD-MIB;\ncollisionUse OBJECT IDENTIFIER ::= { sharedCollision 1 }\nEND\n",
    ),
];

fn load_trace_fixture(strictness: ResolverStrictness) -> mib_rs::Mib {
    Loader::new()
        .source(memory_modules(MODULES))
        .resolver_strictness(strictness)
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("trace fixture should load")
}

#[test]
fn structured_trace_exposes_direct_forwarded_partial_and_failed_import_paths() {
    let mib = load_trace_fixture(ResolverStrictness::Normal);

    let direct = mib
        .trace_symbol("TRACE-SCOPE-MIB::directSymbol", None, ResolutionDomain::Oid)
        .expect("direct trace");
    assert_eq!(direct.outcome, ResolutionOutcome::Resolved);
    assert_eq!(
        direct.target.unwrap().strategy,
        ResolutionStrategy::DirectImport
    );
    let direct_import = direct.import.expect("direct import provenance");
    assert_eq!(direct_import.mode, ImportResolutionMode::Direct);
    assert_eq!(direct_import.selected_path.len(), 1);
    assert!(
        direct_import
            .attempts
            .iter()
            .any(|attempt| attempt.selected)
    );

    let forwarded = mib
        .trace_symbol("TRACE-SCOPE-MIB::traceSymbol", None, ResolutionDomain::Oid)
        .expect("forwarded trace");
    assert_eq!(forwarded.strictness, ResolverStrictness::Normal);
    assert_eq!(
        forwarded.scope.as_ref().unwrap().module_name,
        "TRACE-SCOPE-MIB"
    );
    assert_eq!(forwarded.outcome, ResolutionOutcome::Resolved);
    assert_eq!(
        forwarded.target.unwrap().strategy,
        ResolutionStrategy::ForwardedImport
    );
    let forwarded_import = forwarded.import.expect("forwarding provenance");
    assert_eq!(forwarded_import.mode, ImportResolutionMode::Forwarded);
    assert_eq!(forwarded_import.selected_path.len(), 2);
    assert_eq!(forwarded_import.attempts.len(), 2);
    assert_eq!(
        forwarded_import.attempts[0].outcome,
        ImportAttemptOutcome::SymbolNotDefined
    );
    assert!(!forwarded_import.attempts[0].selected);
    assert_eq!(
        forwarded_import.attempts[1].outcome,
        ImportAttemptOutcome::Resolved
    );
    assert!(forwarded_import.attempts[1].selected);
    assert_eq!(
        forwarded_import
            .selected_path
            .iter()
            .map(|module| mib.module_by_id(*module).name())
            .collect::<Vec<_>>(),
        ["TRACE-FORWARDER-MIB", "TRACE-DEFINER-MIB"]
    );

    let partial = mib
        .trace_symbol(
            "TRACE-PARTIAL-USER-MIB::partialGood",
            None,
            ResolutionDomain::Oid,
        )
        .expect("partial success trace");
    assert_eq!(
        partial.target.unwrap().strategy,
        ResolutionStrategy::PartialImport
    );
    assert_eq!(partial.import.unwrap().mode, ImportResolutionMode::Partial);

    let partial_missing = mib
        .trace_symbol(
            "TRACE-PARTIAL-USER-MIB::partialMissing",
            None,
            ResolutionDomain::Oid,
        )
        .expect("partial failure trace");
    assert_eq!(partial_missing.outcome, ResolutionOutcome::Missing);
    let partial_import = partial_missing.import.expect("partial failure provenance");
    assert_eq!(partial_import.mode, ImportResolutionMode::Partial);
    assert!(partial_import.selected_path.is_empty());
    assert_eq!(
        partial_import.attempts[0].outcome,
        ImportAttemptOutcome::SymbolNotDefined
    );

    let cyclic = mib
        .trace_symbol(
            "TRACE-CYCLE-A-MIB::cyclicSymbol",
            None,
            ResolutionDomain::Oid,
        )
        .expect("cyclic trace");
    let cyclic_import = cyclic.import.expect("cycle provenance");
    assert_eq!(cyclic_import.mode, ImportResolutionMode::Cycle);
    assert!(
        cyclic_import
            .attempts
            .iter()
            .any(|attempt| attempt.outcome == ImportAttemptOutcome::Cycle)
    );
    let cycle_path = &cyclic_import.attempts[0].path;
    assert_eq!(cycle_path.first(), cycle_path.last());

    let missing = mib
        .trace_symbol(
            "TRACE-MISSING-MIB::nowhereSymbol",
            None,
            ResolutionDomain::Oid,
        )
        .expect("missing module trace");
    let missing_import = missing.import.expect("missing module provenance");
    assert_eq!(missing_import.mode, ImportResolutionMode::Unresolved);
    assert_eq!(missing_import.attempts[0].path, []);
    assert_eq!(
        missing_import.attempts[0].missing_module.as_deref(),
        Some("TRACE-ABSENT-MIB")
    );

    let alias = mib
        .trace_symbol(
            "TRACE-ALIAS-USER-MIB::aliasSymbol",
            None,
            ResolutionDomain::Oid,
        )
        .expect("alias trace");
    let alias_import = alias.import.expect("alias provenance");
    assert_eq!(alias_import.mode, ImportResolutionMode::Alias);
    assert_eq!(alias_import.attempts.len(), 1);
    assert_eq!(alias_import.attempts[0].stage, ImportResolutionStage::Alias);
    assert!(alias_import.attempts[0].selected);
}

#[test]
fn trace_uses_domain_specific_fallback_rules() {
    let strict = load_trace_fixture(ResolverStrictness::Strict);
    let normal = load_trace_fixture(ResolverStrictness::Normal);
    let permissive = load_trace_fixture(ResolverStrictness::Permissive);

    let primitive = strict
        .trace_symbol("TRACE-SCOPE-MIB::INTEGER", None, ResolutionDomain::Type)
        .unwrap();
    assert_eq!(
        primitive.target.unwrap().strategy,
        ResolutionStrategy::IntrinsicFallback
    );

    let strict_integer32 = strict
        .trace_symbol("TRACE-SCOPE-MIB::Integer32", None, ResolutionDomain::Type)
        .unwrap();
    assert_eq!(strict_integer32.outcome, ResolutionOutcome::Missing);
    let normal_integer32 = normal
        .trace_symbol("TRACE-SCOPE-MIB::Integer32", None, ResolutionDomain::Type)
        .unwrap();
    assert_eq!(
        normal_integer32.target.unwrap().strategy,
        ResolutionStrategy::ConstrainedFallback
    );

    let global_oid = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::ambiguousTrace",
            None,
            ResolutionDomain::Oid,
        )
        .unwrap();
    assert!(!global_oid.fallbacks.global);
    assert_eq!(global_oid.outcome, ResolutionOutcome::Missing);

    let global_member = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::ambiguousTrace",
            None,
            ResolutionDomain::GroupMember,
        )
        .unwrap();
    assert!(global_member.fallbacks.global);
    assert_eq!(
        global_member.target.unwrap().strategy,
        ResolutionStrategy::GlobalFallback
    );
}

#[test]
fn oid_intrinsic_roots_precede_local_and_imported_shadows() {
    let mib = load_trace_fixture(ResolverStrictness::Normal);
    assert_eq!(
        mib.module("TRACE-LOCAL-OID-SHADOW-MIB")
            .unwrap()
            .node("shadowUse")
            .unwrap()
            .oid()
            .to_string(),
        "1.1"
    );
    assert_eq!(
        mib.module("TRACE-IMPORTED-OID-SHADOW-MIB")
            .unwrap()
            .node("shadowUse")
            .unwrap()
            .oid()
            .to_string(),
        "1.2"
    );
    for scope in [
        "TRACE-LOCAL-OID-SHADOW-MIB",
        "TRACE-IMPORTED-OID-SHADOW-MIB",
    ] {
        let trace = mib
            .trace_symbol(&format!("{scope}::iso"), None, ResolutionDomain::Oid)
            .unwrap();
        let target = trace.target.unwrap();
        assert_eq!(target.strategy, ResolutionStrategy::IntrinsicFallback);
        assert_eq!(target.candidate.module_name, "SNMPv2-SMI");
    }
    assert_eq!(
        mib.trace_symbol(
            "TRACE-IMPORTED-OID-SHADOW-MIB::iso",
            None,
            ResolutionDomain::Oid,
        )
        .unwrap()
        .import
        .unwrap()
        .declared_module,
        "TRACE-OID-SHADOW-MIB"
    );
}

#[test]
fn split_reference_domains_follow_kind_and_lookup_precedence() {
    let normal = load_trace_fixture(ResolverStrictness::Normal);
    let permissive = load_trace_fixture(ResolverStrictness::Permissive);

    let group = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::globalObject",
            None,
            ResolutionDomain::GroupMember,
        )
        .unwrap();
    assert_eq!(group.target.unwrap().strategy, ResolutionStrategy::Local);

    let conformance = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::globalObject",
            None,
            ResolutionDomain::Conformance,
        )
        .unwrap();
    assert_eq!(
        conformance.target.unwrap().strategy,
        ResolutionStrategy::Local
    );

    let notification_normal = normal
        .trace_symbol(
            "TRACE-SCOPE-MIB::globalObject",
            None,
            ResolutionDomain::NotificationObject,
        )
        .unwrap();
    assert_eq!(notification_normal.outcome, ResolutionOutcome::Missing);
    let notification_permissive = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::globalObject",
            None,
            ResolutionDomain::NotificationObject,
        )
        .unwrap();
    let notification_target = notification_permissive.target.unwrap();
    assert_eq!(
        notification_target.strategy,
        ResolutionStrategy::GlobalFallback
    );
    assert_eq!(notification_target.candidate.module_name, "GLOBAL-MIB");

    let object = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::globalObject",
            None,
            ResolutionDomain::Object,
        )
        .unwrap();
    assert_eq!(object.target.unwrap().candidate.module_name, "GLOBAL-MIB");
    let index_object = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::globalObject",
            None,
            ResolutionDomain::Index,
        )
        .unwrap();
    assert_eq!(
        index_object.target.unwrap().candidate.module_name,
        "GLOBAL-MIB"
    );

    let bare_index = normal
        .trace_symbol("TRACE-SCOPE-MIB::Integer32", None, ResolutionDomain::Index)
        .unwrap();
    let bare_target = bare_index.target.unwrap();
    assert_eq!(
        bare_target.strategy,
        ResolutionStrategy::ConstrainedFallback
    );
    assert_eq!(bare_target.candidate.kind, ResolutionCandidateKind::Type);
    assert_eq!(bare_target.candidate.module_name, "SNMPv2-SMI");
    let bare_permissive = permissive
        .trace_symbol("TRACE-SCOPE-MIB::Integer32", None, ResolutionDomain::Index)
        .unwrap();
    assert!(!bare_permissive.fallbacks.global);
}

#[test]
fn scoped_node_domains_preserve_exact_local_and_imported_module_provenance() {
    let mib = load_trace_fixture(ResolverStrictness::Normal);
    assert_eq!(
        mib.node("sharedCollision")
            .unwrap()
            .module()
            .unwrap()
            .name(),
        "TRACE-COLLISION-Z-NEW-MIB",
        "fixture must attach the globally winning shared node to the newer module"
    );

    for domain in [
        ResolutionDomain::Oid,
        ResolutionDomain::GroupMember,
        ResolutionDomain::Conformance,
    ] {
        let local = mib
            .trace_symbol("TRACE-COLLISION-A-OLD-MIB::sharedCollision", None, domain)
            .unwrap();
        let local_target = local.target.unwrap().candidate;
        assert_eq!(local_target.module_name, "TRACE-COLLISION-A-OLD-MIB");
        assert_eq!(
            local_target.source_label.as_deref(),
            Some("<memory:TRACE-COLLISION-A-OLD-MIB>")
        );
        assert_eq!(local_target.kind, ResolutionCandidateKind::Node);
        assert_eq!(local_target.symbol.name(&mib), "sharedCollision");
        assert_eq!(local_target.oid.unwrap().to_string(), "1.424295");
        assert_eq!(local_target.module, local.scope.unwrap().module);

        let imported = mib
            .trace_symbol(
                "TRACE-COLLISION-IMPORTER-MIB::sharedCollision",
                None,
                domain,
            )
            .unwrap();
        let import = imported.import.as_ref().unwrap();
        let imported_target = imported.target.unwrap().candidate;
        assert_eq!(imported_target.module, import.target.unwrap());
        assert_eq!(imported_target.module_name, "TRACE-COLLISION-A-OLD-MIB");
        assert_eq!(
            imported_target.source_label.as_deref(),
            Some("<memory:TRACE-COLLISION-A-OLD-MIB>")
        );
        assert_eq!(imported_target.kind, ResolutionCandidateKind::Node);
        assert_eq!(imported_target.symbol.name(&mib), "sharedCollision");
        assert_eq!(imported_target.oid.unwrap().to_string(), "1.424295");
    }

    let permissive = load_trace_fixture(ResolverStrictness::Permissive);
    for domain in [ResolutionDomain::GroupMember, ResolutionDomain::Conformance] {
        let trace = permissive
            .trace_symbol("TRACE-SCOPE-MIB::sharedCollision", None, domain)
            .unwrap();
        let target = trace.target.unwrap();
        assert_eq!(target.strategy, ResolutionStrategy::GlobalFallback);
        assert_eq!(target.candidate.module_name, "TRACE-COLLISION-A-OLD-MIB");
        assert_eq!(
            target.candidate.source_label.as_deref(),
            Some("<memory:TRACE-COLLISION-A-OLD-MIB>")
        );
    }

    let notification = permissive
        .trace_symbol(
            "TRACE-SCOPE-MIB::sharedCollision",
            None,
            ResolutionDomain::NotificationObject,
        )
        .unwrap();
    let notification_target = notification.target.unwrap();
    assert_eq!(
        notification_target.strategy,
        ResolutionStrategy::GlobalFallback
    );
    assert_eq!(
        notification_target.candidate.module_name,
        "TRACE-COLLISION-Z-NEW-MIB"
    );
    assert_eq!(
        notification_target.candidate.kind,
        ResolutionCandidateKind::Object
    );
}

#[test]
fn trace_reports_unscoped_ambiguity() {
    let mib = load_trace_fixture(ResolverStrictness::Normal);
    let ambiguous = mib
        .trace_symbol("ambiguousTrace", None, ResolutionDomain::Oid)
        .expect("unscoped trace");
    assert_eq!(ambiguous.outcome, ResolutionOutcome::Ambiguous);
    assert_eq!(
        ambiguous
            .candidates
            .iter()
            .map(|candidate| candidate.module_name.as_str())
            .collect::<Vec<_>>(),
        ["TRACE-ALPHA-MIB", "TRACE-ZETA-MIB"]
    );
}

#[test]
fn trace_lists_cross_kind_candidates_and_selects_the_requested_domain() {
    const COLLISION_MODULES: [(&str, &[u8]); 1] = [(
        "TRACE-COLLISION-MIB",
        b"TRACE-COLLISION-MIB DEFINITIONS ::= BEGIN\ncollisionName ::= INTEGER\ncollisionName OBJECT IDENTIFIER ::= { iso 424292 }\nEND\n",
    )];
    let mib = Loader::new()
        .source(memory_modules(COLLISION_MODULES))
        .diagnostic_config(DiagnosticConfig::silent())
        .load()
        .expect("kind collision fixture should load");

    let type_trace = mib
        .trace_symbol(
            "TRACE-COLLISION-MIB::collisionName",
            None,
            ResolutionDomain::Type,
        )
        .unwrap();
    assert_eq!(type_trace.candidates.len(), 2);
    assert_eq!(
        type_trace
            .candidates
            .iter()
            .map(|candidate| candidate.kind)
            .collect::<Vec<_>>(),
        [ResolutionCandidateKind::Type, ResolutionCandidateKind::Node]
    );
    assert_eq!(
        type_trace.target.unwrap().candidate.kind,
        ResolutionCandidateKind::Type
    );

    let oid_trace = mib
        .trace_symbol(
            "TRACE-COLLISION-MIB::collisionName",
            None,
            ResolutionDomain::Oid,
        )
        .unwrap();
    assert_eq!(
        oid_trace.target.unwrap().candidate.kind,
        ResolutionCandidateKind::Node
    );
}
