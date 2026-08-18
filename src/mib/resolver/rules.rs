//! Shared resolver fallback rules used by resolution and structured tracing.

use crate::types::{ResolutionDomain, ResolverStrictness};

pub(crate) fn intrinsic_foundation_module(
    domain: ResolutionDomain,
    symbol: &str,
) -> Option<&'static str> {
    match domain {
        ResolutionDomain::Type
            if matches!(
                symbol,
                "INTEGER" | "OCTET STRING" | "OBJECT IDENTIFIER" | "BITS"
            ) =>
        {
            Some("SNMPv2-SMI")
        }
        ResolutionDomain::Oid if matches!(symbol, "iso" | "ccitt" | "joint-iso-ccitt") => {
            Some("SNMPv2-SMI")
        }
        _ => None,
    }
}

pub(crate) fn constrained_foundation_modules(
    domain: ResolutionDomain,
    strictness: ResolverStrictness,
) -> &'static [&'static str] {
    if !strictness.allow_constrained_fallbacks() {
        return &[];
    }
    match domain {
        ResolutionDomain::Type => &["SNMPv2-SMI", "RFC1155-SMI", "SNMPv2-TC"],
        ResolutionDomain::Oid => &["SNMPv2-SMI", "RFC1155-SMI"],
        ResolutionDomain::Object
        | ResolutionDomain::GroupMember
        | ResolutionDomain::Index
        | ResolutionDomain::NotificationObject
        | ResolutionDomain::Conformance => &[],
    }
}

pub(crate) fn allows_global_fallback(
    domain: ResolutionDomain,
    strictness: ResolverStrictness,
) -> bool {
    strictness.allow_global_fallbacks()
        && matches!(
            domain,
            ResolutionDomain::Object
                | ResolutionDomain::GroupMember
                | ResolutionDomain::Index
                | ResolutionDomain::NotificationObject
                | ResolutionDomain::Conformance
        )
}

pub(crate) fn is_bare_index_type(symbol: &str) -> bool {
    matches!(
        symbol,
        "INTEGER"
            | "OCTET STRING"
            | "BITS"
            | "Integer32"
            | "Counter32"
            | "Counter64"
            | "Gauge32"
            | "Unsigned32"
            | "TimeTicks"
            | "IpAddress"
            | "Opaque"
            | "Counter"
            | "Gauge"
            | "NetworkAddress"
    )
}

pub(crate) fn fallback_domain(domain: ResolutionDomain, symbol: &str) -> ResolutionDomain {
    if domain == ResolutionDomain::Index && is_bare_index_type(symbol) {
        ResolutionDomain::Type
    } else {
        domain
    }
}

pub(crate) fn allows_trap_enterprise_fallback(strictness: ResolverStrictness) -> bool {
    strictness.allow_constrained_fallbacks()
}
