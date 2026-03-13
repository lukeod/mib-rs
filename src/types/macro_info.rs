//! Reference table for SMI macro keywords.
//!
//! Provides [`MacroInfo`] descriptions for the 10 standard SMI macro keywords
//! (OBJECT-TYPE, MODULE-IDENTITY, TEXTUAL-CONVENTION, etc.), including their
//! defining module, RFC, and a brief description.

/// Describes an SMI macro keyword (e.g. OBJECT-TYPE, MODULE-IDENTITY).
///
/// See [`macro_description`] to look up a macro by name.
pub struct MacroInfo {
    /// The macro keyword (e.g. "OBJECT-TYPE").
    pub name: &'static str,
    /// The defining module (e.g. "SNMPv2-SMI").
    pub module: &'static str,
    /// The defining RFC (e.g. "RFC 2578").
    pub rfc: &'static str,
    /// Brief description of what the macro defines.
    pub description: &'static str,
}

/// Returns info about an SMI macro keyword, or `None` if the name is not recognized.
///
/// Covers the 10 standard macros across SMIv1 and SMIv2: OBJECT-TYPE,
/// MODULE-IDENTITY, OBJECT-IDENTITY, NOTIFICATION-TYPE, TEXTUAL-CONVENTION,
/// TRAP-TYPE, OBJECT-GROUP, NOTIFICATION-GROUP, MODULE-COMPLIANCE, and
/// AGENT-CAPABILITIES.
pub fn macro_description(name: &str) -> Option<&'static MacroInfo> {
    MACRO_INFO_TABLE.iter().find(|info| info.name == name)
}

static MACRO_INFO_TABLE: &[MacroInfo] = &[
    MacroInfo {
        name: "OBJECT-TYPE",
        module: "SNMPv2-SMI",
        rfc: "RFC 2578",
        description: "Defines a managed object: its syntax, access level, status, and position in the OID tree.",
    },
    MacroInfo {
        name: "MODULE-IDENTITY",
        module: "SNMPv2-SMI",
        rfc: "RFC 2578",
        description: "Provides contact, revision history, and description metadata for a MIB module. Also assigns the module's root OID.",
    },
    MacroInfo {
        name: "OBJECT-IDENTITY",
        module: "SNMPv2-SMI",
        rfc: "RFC 2578",
        description: "Assigns a name and description to an OID without defining a managed object. Used for administrative OID registrations.",
    },
    MacroInfo {
        name: "NOTIFICATION-TYPE",
        module: "SNMPv2-SMI",
        rfc: "RFC 2578",
        description: "Defines an SNMPv2 notification (trap) with a list of associated objects.",
    },
    MacroInfo {
        name: "TEXTUAL-CONVENTION",
        module: "SNMPv2-TC",
        rfc: "RFC 2579",
        description: "Defines a named type with a display hint, status, and description. Used to give semantic meaning to base types.",
    },
    MacroInfo {
        name: "TRAP-TYPE",
        module: "RFC-1215",
        rfc: "RFC 1215",
        description: "Defines an SNMPv1 trap with an enterprise OID and trap number. Superseded by NOTIFICATION-TYPE in SMIv2.",
    },
    MacroInfo {
        name: "OBJECT-GROUP",
        module: "SNMPv2-CONF",
        rfc: "RFC 2580",
        description: "Defines a collection of related OBJECT-TYPE definitions for conformance purposes.",
    },
    MacroInfo {
        name: "NOTIFICATION-GROUP",
        module: "SNMPv2-CONF",
        rfc: "RFC 2580",
        description: "Defines a collection of related NOTIFICATION-TYPE definitions for conformance purposes.",
    },
    MacroInfo {
        name: "MODULE-COMPLIANCE",
        module: "SNMPv2-CONF",
        rfc: "RFC 2580",
        description: "Specifies minimum conformance requirements for implementing a MIB module, including mandatory groups and optional refinements.",
    },
    MacroInfo {
        name: "AGENT-CAPABILITIES",
        module: "SNMPv2-CONF",
        rfc: "RFC 2580",
        description: "Documents the exact MIB support provided by an SNMP agent, including supported modules and any variations from full compliance.",
    },
];
