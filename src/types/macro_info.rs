/// Describes an SMI macro keyword.
pub struct MacroInfo {
    pub name: &'static str,
    pub module: &'static str,
    pub rfc: &'static str,
    pub description: &'static str,
}

/// Returns info about an SMI macro keyword, if known.
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
