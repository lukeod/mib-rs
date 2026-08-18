//! Embedded source and metadata for the seven SMI foundation modules.
//!
//! The embedded RFC-derived module source is byte-synchronized with gomib and
//! includes deliberate adaptations. It is parsed through the normal loading
//! pipeline when a configured source does not provide a foundation module.
//! Keeping the fallback as source text gives foundation definitions ordinary
//! source spans and lets explicitly supplied copies take precedence.

use crate::types::Language;

/// Metadata for a recognized foundation module.
pub struct BaseModuleInfo {
    /// Canonical module name, for example SNMPv2-SMI.
    pub name: &'static str,
    /// SMI language version of this foundation module.
    pub language: Language,
}

const BASE_MODULES: &[BaseModuleInfo] = &[
    BaseModuleInfo {
        name: "SNMPv2-SMI",
        language: Language::SMIv2,
    },
    BaseModuleInfo {
        name: "SNMPv2-TC",
        language: Language::SMIv2,
    },
    BaseModuleInfo {
        name: "SNMPv2-CONF",
        language: Language::SMIv2,
    },
    BaseModuleInfo {
        name: "RFC1155-SMI",
        language: Language::SMIv1,
    },
    BaseModuleInfo {
        name: "RFC1065-SMI",
        language: Language::SMIv1,
    },
    BaseModuleInfo {
        name: "RFC-1212",
        language: Language::SMIv1,
    },
    BaseModuleInfo {
        name: "RFC-1215",
        language: Language::SMIv1,
    },
];

/// Reports whether name is a recognized foundation module.
pub fn is_base_module(name: &str) -> bool {
    base_module_from_name(name).is_some()
}

/// Returns the BaseModuleInfo for the given name, if any.
pub fn base_module_from_name(name: &str) -> Option<&'static BaseModuleInfo> {
    BASE_MODULES.iter().find(|module| module.name == name)
}

/// Returns the canonical names of all foundation modules.
pub fn base_module_names() -> &'static [&'static str] {
    static NAMES: &[&str] = &[
        "SNMPv2-SMI",
        "SNMPv2-TC",
        "SNMPv2-CONF",
        "RFC1155-SMI",
        "RFC1065-SMI",
        "RFC-1212",
        "RFC-1215",
    ];
    NAMES
}

/// Return the embedded RFC-derived module source for a foundation module.
pub(crate) fn embedded_content(name: &str) -> Option<&'static [u8]> {
    match name {
        "SNMPv2-SMI" => Some(include_bytes!("embedded/SNMPv2-SMI")),
        "SNMPv2-TC" => Some(include_bytes!("embedded/SNMPv2-TC")),
        "SNMPv2-CONF" => Some(include_bytes!("embedded/SNMPv2-CONF")),
        "RFC1155-SMI" => Some(include_bytes!("embedded/RFC1155-SMI")),
        "RFC1065-SMI" => Some(include_bytes!("embedded/RFC1065-SMI")),
        "RFC-1212" => Some(include_bytes!("embedded/RFC-1212")),
        "RFC-1215" => Some(include_bytes!("embedded/RFC-1215")),
        _ => None,
    }
}
