/// Describes an SMI clause keyword used within a macro definition (e.g. SYNTAX, STATUS, INDEX).
///
/// See [`clause_description`] to look up a clause by name.
pub struct ClauseInfo {
    /// The clause keyword (e.g. "SYNTAX", "MAX-ACCESS").
    pub name: &'static str,
    /// Macro definitions that contain this clause.
    pub macros: &'static [&'static str],
    /// The primary defining RFC.
    pub rfc: &'static str,
    /// Brief description of the clause's purpose.
    pub description: &'static str,
}

/// Returns info about an SMI clause keyword, or `None` if the name is not recognized.
pub fn clause_description(name: &str) -> Option<&'static ClauseInfo> {
    CLAUSE_INFO_TABLE.iter().find(|info| info.name == name)
}

static CLAUSE_INFO_TABLE: &[ClauseInfo] = &[
    ClauseInfo {
        name: "SYNTAX",
        macros: &[
            "OBJECT-TYPE",
            "TEXTUAL-CONVENTION",
            "MODULE-COMPLIANCE",
            "AGENT-CAPABILITIES",
        ],
        rfc: "RFC 2578",
        description: "Specifies the ASN.1 type of a managed object or textual convention.",
    },
    ClauseInfo {
        name: "MAX-ACCESS",
        macros: &["OBJECT-TYPE"],
        rfc: "RFC 2578",
        description: "Specifies the maximum access level for a managed object.",
    },
    ClauseInfo {
        name: "MIN-ACCESS",
        macros: &["MODULE-COMPLIANCE"],
        rfc: "RFC 2580",
        description: "Specifies the minimum required access level when granting a compliance exception.",
    },
    ClauseInfo {
        name: "ACCESS",
        macros: &["OBJECT-TYPE", "AGENT-CAPABILITIES"],
        rfc: "RFC 1155",
        description: "Specifies the access level for an SMIv1 managed object or an agent capability variation.",
    },
    ClauseInfo {
        name: "STATUS",
        macros: &[
            "OBJECT-TYPE",
            "MODULE-IDENTITY",
            "OBJECT-IDENTITY",
            "NOTIFICATION-TYPE",
            "TEXTUAL-CONVENTION",
            "OBJECT-GROUP",
            "NOTIFICATION-GROUP",
            "MODULE-COMPLIANCE",
            "AGENT-CAPABILITIES",
        ],
        rfc: "RFC 2578",
        description: "Indicates the lifecycle state of a definition: current, deprecated, or obsolete.",
    },
    ClauseInfo {
        name: "DESCRIPTION",
        macros: &[
            "OBJECT-TYPE",
            "MODULE-IDENTITY",
            "OBJECT-IDENTITY",
            "NOTIFICATION-TYPE",
            "TEXTUAL-CONVENTION",
            "OBJECT-GROUP",
            "NOTIFICATION-GROUP",
            "MODULE-COMPLIANCE",
            "AGENT-CAPABILITIES",
            "TRAP-TYPE",
        ],
        rfc: "RFC 2578",
        description: "Provides a human-readable text description of the definition.",
    },
    ClauseInfo {
        name: "REFERENCE",
        macros: &[
            "OBJECT-TYPE",
            "OBJECT-IDENTITY",
            "NOTIFICATION-TYPE",
            "TEXTUAL-CONVENTION",
            "OBJECT-GROUP",
            "NOTIFICATION-GROUP",
            "MODULE-COMPLIANCE",
            "AGENT-CAPABILITIES",
            "TRAP-TYPE",
        ],
        rfc: "RFC 2578",
        description: "Provides a cross-reference to another document or definition.",
    },
    ClauseInfo {
        name: "DEFVAL",
        macros: &["OBJECT-TYPE", "AGENT-CAPABILITIES"],
        rfc: "RFC 2578",
        description: "Specifies an acceptable default value for a managed object when creating a new row.",
    },
    ClauseInfo {
        name: "UNITS",
        macros: &["OBJECT-TYPE"],
        rfc: "RFC 2578",
        description: "Specifies a textual description of the units (e.g. \"seconds\") associated with the object.",
    },
    ClauseInfo {
        name: "INDEX",
        macros: &["OBJECT-TYPE"],
        rfc: "RFC 2578",
        description: "Specifies the set of objects whose values uniquely identify a conceptual row in a table.",
    },
    ClauseInfo {
        name: "IMPLIED",
        macros: &["OBJECT-TYPE"],
        rfc: "RFC 2578",
        description: "Indicates the last INDEX object has an implied length, omitting the length prefix from the instance identifier.",
    },
    ClauseInfo {
        name: "AUGMENTS",
        macros: &["OBJECT-TYPE"],
        rfc: "RFC 2578",
        description: "Specifies that this row extends (augments) another table's row, sharing its INDEX.",
    },
    ClauseInfo {
        name: "DISPLAY-HINT",
        macros: &["TEXTUAL-CONVENTION"],
        rfc: "RFC 2579",
        description: "Provides a hint for how the value should be displayed to a human operator.",
    },
    ClauseInfo {
        name: "OBJECTS",
        macros: &["NOTIFICATION-TYPE", "OBJECT-GROUP"],
        rfc: "RFC 2578",
        description: "Lists the objects associated with a notification or the members of a group.",
    },
    ClauseInfo {
        name: "NOTIFICATIONS",
        macros: &["NOTIFICATION-GROUP"],
        rfc: "RFC 2580",
        description: "Lists the notifications that are members of this group.",
    },
    ClauseInfo {
        name: "MODULE",
        macros: &["MODULE-COMPLIANCE"],
        rfc: "RFC 2580",
        description: "Identifies a module and its mandatory groups within a compliance statement.",
    },
    ClauseInfo {
        name: "MANDATORY-GROUPS",
        macros: &["MODULE-COMPLIANCE"],
        rfc: "RFC 2580",
        description: "Lists the groups that must be implemented for compliance with this module.",
    },
    ClauseInfo {
        name: "GROUP",
        macros: &["MODULE-COMPLIANCE"],
        rfc: "RFC 2580",
        description: "Specifies a conditionally mandatory group within a compliance statement.",
    },
    ClauseInfo {
        name: "OBJECT",
        macros: &["MODULE-COMPLIANCE"],
        rfc: "RFC 2580",
        description: "Names an object for which compliance refinements (syntax, access, write-syntax) are specified.",
    },
    ClauseInfo {
        name: "WRITE-SYNTAX",
        macros: &["MODULE-COMPLIANCE", "AGENT-CAPABILITIES"],
        rfc: "RFC 2580",
        description: "Specifies a restricted syntax that applies when writing (setting) this object.",
    },
    ClauseInfo {
        name: "PRODUCT-RELEASE",
        macros: &["AGENT-CAPABILITIES"],
        rfc: "RFC 2580",
        description: "Identifies the product release associated with the agent capabilities statement.",
    },
    ClauseInfo {
        name: "SUPPORTS",
        macros: &["AGENT-CAPABILITIES"],
        rfc: "RFC 2580",
        description: "Identifies a MIB module supported by the agent.",
    },
    ClauseInfo {
        name: "INCLUDES",
        macros: &["AGENT-CAPABILITIES"],
        rfc: "RFC 2580",
        description: "Lists the groups from a supported module that the agent implements.",
    },
    ClauseInfo {
        name: "VARIATION",
        macros: &["AGENT-CAPABILITIES"],
        rfc: "RFC 2580",
        description: "Describes a deviation from the standard definition of an object.",
    },
    ClauseInfo {
        name: "CREATION-REQUIRES",
        macros: &["AGENT-CAPABILITIES"],
        rfc: "RFC 2580",
        description: "Lists the objects that must be set to create a new conceptual row.",
    },
    ClauseInfo {
        name: "REVISION",
        macros: &["MODULE-IDENTITY"],
        rfc: "RFC 2578",
        description: "Documents a revision of the MIB module with a date and description.",
    },
    ClauseInfo {
        name: "LAST-UPDATED",
        macros: &["MODULE-IDENTITY"],
        rfc: "RFC 2578",
        description: "Specifies the date and time the module was last modified.",
    },
    ClauseInfo {
        name: "ORGANIZATION",
        macros: &["MODULE-IDENTITY"],
        rfc: "RFC 2578",
        description: "Identifies the organization responsible for the MIB module.",
    },
    ClauseInfo {
        name: "CONTACT-INFO",
        macros: &["MODULE-IDENTITY"],
        rfc: "RFC 2578",
        description: "Provides contact information for the module's maintainer.",
    },
    ClauseInfo {
        name: "ENTERPRISE",
        macros: &["TRAP-TYPE"],
        rfc: "RFC 1215",
        description: "Specifies the enterprise OID under which the SMIv1 trap is defined.",
    },
    ClauseInfo {
        name: "VARIABLES",
        macros: &["TRAP-TYPE"],
        rfc: "RFC 1215",
        description: "Lists the objects included in an SMIv1 trap.",
    },
    ClauseInfo {
        name: "SIZE",
        macros: &["OBJECT-TYPE", "TEXTUAL-CONVENTION"],
        rfc: "RFC 2578",
        description: "Constrains the length of an OCTET STRING or the number of elements in a BITS value.",
    },
];
