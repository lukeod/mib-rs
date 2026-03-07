use std::sync::LazyLock;

use crate::ir;
use crate::types::{BaseType, Language, Span, Status};

/// Base module metadata for lookup.
pub struct BaseModuleInfo {
    pub name: &'static str,
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

/// Reports whether name is a recognized base module.
pub fn is_base_module(name: &str) -> bool {
    base_module_from_name(name).is_some()
}

/// Returns the BaseModuleInfo for the given name, if any.
pub fn base_module_from_name(name: &str) -> Option<&'static BaseModuleInfo> {
    BASE_MODULES.iter().find(|bm| bm.name == name)
}

/// Returns the canonical names of all base modules.
pub fn base_module_names() -> Vec<&'static str> {
    BASE_MODULES.iter().map(|bm| bm.name).collect()
}

/// Returns synthetic Module IR values for all base modules.
/// These should be prepended to the user module list before resolution.
pub fn create_base_modules() -> Vec<ir::Module> {
    vec![
        create_snmpv2_smi(),
        create_snmpv2_tc(),
        create_snmpv2_conf(),
        create_smiv1_base("RFC1155-SMI"),
        create_smiv1_base("RFC1065-SMI"),
        create_rfc1212(),
        create_rfc1215(),
    ]
}

static CACHED_BASE_MODULES: LazyLock<Vec<ir::Module>> = LazyLock::new(create_base_modules);

/// Returns a reference to the cached base module with the given name, or None.
pub fn get_base_module(name: &str) -> Option<&'static ir::Module> {
    CACHED_BASE_MODULES.iter().find(|m| m.name == name)
}

// --- Module constructors ---

fn create_snmpv2_smi() -> ir::Module {
    let mut module = ir::Module::new("SNMPv2-SMI".into(), Span::SYNTHETIC);
    module.language = Language::SMIv2;
    module.definitions = create_oid_definitions();
    module
        .definitions
        .extend(create_base_type_definitions());
    module
}

fn create_snmpv2_tc() -> ir::Module {
    let mut module = ir::Module::new("SNMPv2-TC".into(), Span::SYNTHETIC);
    module.language = Language::SMIv2;
    module.imports = vec![ir::Import {
        module: "SNMPv2-SMI".into(),
        symbol: "TimeTicks".into(),
        span: Span::SYNTHETIC,
    }];
    module.definitions = create_tc_definitions();
    module
}

fn create_snmpv2_conf() -> ir::Module {
    let mut module = ir::Module::new("SNMPv2-CONF".into(), Span::SYNTHETIC);
    module.language = Language::SMIv2;
    module
}

fn create_smiv1_base(name: &str) -> ir::Module {
    let mut module = ir::Module::new(name.into(), Span::SYNTHETIC);
    module.language = Language::SMIv1;
    module.definitions = create_smiv1_type_definitions();
    module
        .definitions
        .extend(core_oid_definitions());
    module
}

fn create_rfc1212() -> ir::Module {
    let mut module = ir::Module::new("RFC-1212".into(), Span::SYNTHETIC);
    module.language = Language::SMIv1;
    module
}

fn create_rfc1215() -> ir::Module {
    let mut module = ir::Module::new("RFC-1215".into(), Span::SYNTHETIC);
    module.language = Language::SMIv1;
    module
}

// --- Type syntax helpers ---

fn constrained_int_range(min: ir::RangeValue, max: ir::RangeValue) -> ir::TypeSyntax {
    ir::TypeSyntax::Constrained {
        base: Box::new(ir::TypeSyntax::TypeRef {
            name: "INTEGER".into(),
            span: Span::SYNTHETIC,
        }),
        constraint: ir::Constraint::Range {
            ranges: vec![ir::Range {
                min,
                max: Some(max),
                span: Span::SYNTHETIC,
            }],
            span: Span::SYNTHETIC,
        },
        span: Span::SYNTHETIC,
    }
}

fn constrained_uint_range(max: u64) -> ir::TypeSyntax {
    constrained_int_range(ir::RangeValue::Unsigned(0), ir::RangeValue::Unsigned(max))
}

fn constrained_octet_size(ranges: Vec<ir::Range>) -> ir::TypeSyntax {
    ir::TypeSyntax::Constrained {
        base: Box::new(ir::TypeSyntax::OctetString),
        constraint: ir::Constraint::Size {
            ranges,
            span: Span::SYNTHETIC,
        },
        span: Span::SYNTHETIC,
    }
}

fn constrained_octet_fixed(size: u64) -> ir::TypeSyntax {
    constrained_octet_size(vec![ir::Range {
        min: ir::RangeValue::Unsigned(size),
        max: None,
        span: Span::SYNTHETIC,
    }])
}

fn constrained_octet_range(min: u64, max: u64) -> ir::TypeSyntax {
    constrained_octet_size(vec![ir::Range {
        min: ir::RangeValue::Unsigned(min),
        max: Some(ir::RangeValue::Unsigned(max)),
        span: Span::SYNTHETIC,
    }])
}

// --- OID definition helpers ---

fn oid_name(name: &str) -> ir::OidComponent {
    ir::OidComponent::Name {
        name: name.into(),
        span: Span::SYNTHETIC,
    }
}

fn oid_num(value: u32) -> ir::OidComponent {
    ir::OidComponent::Number {
        value,
        span: Span::SYNTHETIC,
    }
}

fn make_oid_value(
    name: &str,
    components: Vec<ir::OidComponent>,
    desc: &str,
    reference: &str,
) -> ir::Definition {
    ir::Definition::ValueAssignment(ir::ValueAssignment {
        name: name.into(),
        span: Span::SYNTHETIC,
        oid: ir::OidAssignment {
            components,
            span: Span::SYNTHETIC,
        },
        description: desc.into(),
        reference: reference.into(),
    })
}

fn make_type_def(
    name: &str,
    syntax: ir::TypeSyntax,
    base: Option<BaseType>,
    status: Status,
    desc: &str,
    reference: &str,
) -> ir::Definition {
    ir::Definition::TypeDef(ir::TypeDef {
        name: name.into(),
        span: Span::SYNTHETIC,
        syntax,
        base_type: base,
        display_hint: String::new(),
        status,
        description: desc.into(),
        reference: reference.into(),
        is_textual_convention: false,
        syntax_span: Span::SYNTHETIC,
        status_span: Span::SYNTHETIC,
        description_span: Span::SYNTHETIC,
        reference_span: Span::SYNTHETIC,
        display_hint_span: Span::SYNTHETIC,
    })
}

fn make_tc(
    name: &str,
    display_hint: &str,
    syntax: ir::TypeSyntax,
    status: Status,
    desc: &str,
) -> ir::Definition {
    ir::Definition::TypeDef(ir::TypeDef {
        name: name.into(),
        span: Span::SYNTHETIC,
        syntax,
        base_type: None,
        display_hint: display_hint.into(),
        status,
        description: desc.into(),
        reference: "RFC 2579".into(),
        is_textual_convention: true,
        syntax_span: Span::SYNTHETIC,
        status_span: Span::SYNTHETIC,
        description_span: Span::SYNTHETIC,
        reference_span: Span::SYNTHETIC,
        display_hint_span: Span::SYNTHETIC,
    })
}

fn integer_enum(named_numbers: Vec<ir::NamedNumber>) -> ir::TypeSyntax {
    ir::TypeSyntax::IntegerEnum {
        base: String::new(),
        named_numbers,
        span: Span::SYNTHETIC,
    }
}

fn nn(name: &str, value: i64) -> ir::NamedNumber {
    ir::NamedNumber {
        name: name.into(),
        value,
        span: Span::SYNTHETIC,
    }
}

// --- Core OID definitions shared by SMIv2 and SMIv1 ---

fn core_oid_definitions() -> Vec<ir::Definition> {
    vec![
        make_oid_value("iso", vec![oid_num(1)], "ISO assigned OIDs.", ""),
        make_oid_value(
            "org",
            vec![oid_name("iso"), oid_num(3)],
            "ISO identified organizations.",
            "",
        ),
        make_oid_value(
            "dod",
            vec![oid_name("org"), oid_num(6)],
            "US Department of Defense.",
            "",
        ),
        make_oid_value(
            "internet",
            vec![oid_name("dod"), oid_num(1)],
            "The root of the Internet OID subtree.",
            "RFC 1155",
        ),
        make_oid_value(
            "directory",
            vec![oid_name("internet"), oid_num(1)],
            "Reserved for future use by the OSI directory (X.500).",
            "RFC 1155",
        ),
        make_oid_value(
            "mgmt",
            vec![oid_name("internet"), oid_num(2)],
            "Management subtree. Contains mib-2 and other IANA-managed branches.",
            "RFC 1155",
        ),
        make_oid_value(
            "experimental",
            vec![oid_name("internet"), oid_num(3)],
            "Experimental subtree for Internet experiments.",
            "RFC 1155",
        ),
        make_oid_value(
            "private",
            vec![oid_name("internet"), oid_num(4)],
            "Private subtree. Contains enterprises.",
            "RFC 1155",
        ),
        make_oid_value(
            "enterprises",
            vec![oid_name("private"), oid_num(1)],
            "Vendor-specific OID subtree. Each vendor gets a unique enterprise number from IANA.",
            "RFC 1155",
        ),
    ]
}

fn create_oid_definitions() -> Vec<ir::Definition> {
    let rfc2578 = "RFC 2578";
    let mut defs = vec![
        make_oid_value(
            "ccitt",
            vec![oid_num(0)],
            "ITU-T (formerly CCITT) assigned OIDs.",
            "",
        ),
        make_oid_value(
            "joint-iso-ccitt",
            vec![oid_num(2)],
            "Jointly assigned ISO/ITU-T OIDs.",
            "",
        ),
    ];
    defs.extend(core_oid_definitions());
    defs.extend(vec![
        make_oid_value(
            "mib-2",
            vec![oid_name("mgmt"), oid_num(1)],
            "The MIB-II subtree. Contains standard MIB modules (system, interfaces, IP, etc.).",
            rfc2578,
        ),
        make_oid_value(
            "transmission",
            vec![oid_name("mib-2"), oid_num(10)],
            "Transmission media specific MIBs.",
            rfc2578,
        ),
        make_oid_value(
            "security",
            vec![oid_name("internet"), oid_num(5)],
            "Security subtree for authentication and privacy.",
            rfc2578,
        ),
        make_oid_value(
            "snmpV2",
            vec![oid_name("internet"), oid_num(6)],
            "SNMPv2 subtree. Contains transport domains, proxies, and module registrations.",
            rfc2578,
        ),
        make_oid_value(
            "snmpDomains",
            vec![oid_name("snmpV2"), oid_num(1)],
            "Registration point for SNMP transport domains.",
            rfc2578,
        ),
        make_oid_value(
            "snmpProxys",
            vec![oid_name("snmpV2"), oid_num(2)],
            "Registration point for SNMP proxy types.",
            rfc2578,
        ),
        make_oid_value(
            "snmpModules",
            vec![oid_name("snmpV2"), oid_num(3)],
            "Registration point for SNMP MIB module identities.",
            rfc2578,
        ),
        make_oid_value(
            "zeroDotZero",
            vec![oid_num(0), oid_num(0)],
            "A value used for null identifiers. Used as a default value when no valid OID is applicable.",
            rfc2578,
        ),
        make_oid_value(
            "snmp",
            vec![oid_name("mib-2"), oid_num(11)],
            "SNMP protocol statistics and administrative objects.",
            rfc2578,
        ),
    ]);
    defs
}

fn create_base_type_definitions() -> Vec<ir::Definition> {
    let int32_min = i64::from(i32::MIN);
    let int32_max = i64::from(i32::MAX);
    let uint32_max = u64::from(u32::MAX);
    let uint64_max = u64::MAX;
    let rfc = "RFC 2578, Section 7.1";

    vec![
        make_type_def(
            "Integer32",
            constrained_int_range(
                ir::RangeValue::Signed(int32_min),
                ir::RangeValue::Signed(int32_max),
            ),
            Some(BaseType::Integer32),
            Status::Current,
            "A 32-bit signed integer. The range is -2147483648 to 2147483647.",
            &format!("{}.1", rfc),
        ),
        make_type_def(
            "Counter32",
            constrained_uint_range(uint32_max),
            Some(BaseType::Counter32),
            Status::Current,
            "A non-negative 32-bit counter that monotonically increases until it wraps at 2^32-1. A Counter32 has no defined initial value and must not be used for a MIB object that has a MAX-ACCESS of read-write or read-create.",
            &format!("{}.6", rfc),
        ),
        make_type_def(
            "Counter64",
            constrained_uint_range(uint64_max),
            Some(BaseType::Counter64),
            Status::Current,
            "A non-negative 64-bit counter for high-speed interfaces where Counter32 would wrap too frequently. Counter64 should only be used when Counter32 wrapping is a problem.",
            &format!("{}.8", rfc),
        ),
        make_type_def(
            "Gauge32",
            constrained_uint_range(uint32_max),
            Some(BaseType::Gauge32),
            Status::Current,
            "A non-negative 32-bit integer that may increase or decrease but latches at a maximum value of 2^32-1.",
            &format!("{}.7", rfc),
        ),
        make_type_def(
            "Unsigned32",
            constrained_uint_range(uint32_max),
            Some(BaseType::Unsigned32),
            Status::Current,
            "A 32-bit unsigned integer with range 0 to 4294967295. Shares the same APPLICATION tag as Gauge32.",
            &format!("{}.1", rfc),
        ),
        make_type_def(
            "TimeTicks",
            constrained_uint_range(uint32_max),
            Some(BaseType::TimeTicks),
            Status::Current,
            "A non-negative 32-bit integer representing time in hundredths of a second since some reference epoch.",
            &format!("{}.2", rfc),
        ),
        make_type_def(
            "IpAddress",
            constrained_octet_fixed(4),
            Some(BaseType::IpAddress),
            Status::Current,
            "An IPv4 address represented as a 4-byte OCTET STRING in network byte order. New MIBs should use InetAddress from INET-ADDRESS-MIB instead.",
            &format!("{}.3", rfc),
        ),
        make_type_def(
            "Opaque",
            ir::TypeSyntax::OctetString,
            Some(BaseType::Opaque),
            Status::Current,
            "An arbitrary ASN.1 value encoded as an OCTET STRING for transparent transport. Use of Opaque is discouraged in new MIB definitions.",
            &format!("{}.4", rfc),
        ),
        make_type_def(
            "ObjectName",
            ir::TypeSyntax::ObjectIdentifier,
            None,
            Status::Current,
            "An OBJECT IDENTIFIER value that names a managed object.",
            rfc,
        ),
        make_type_def(
            "NotificationName",
            ir::TypeSyntax::ObjectIdentifier,
            None,
            Status::Current,
            "An OBJECT IDENTIFIER value that names a notification.",
            rfc,
        ),
        make_type_def(
            "ExtUTCTime",
            constrained_octet_size(vec![
                ir::Range {
                    min: ir::RangeValue::Unsigned(11),
                    max: None,
                    span: Span::SYNTHETIC,
                },
                ir::Range {
                    min: ir::RangeValue::Unsigned(13),
                    max: None,
                    span: Span::SYNTHETIC,
                },
            ]),
            None,
            Status::Obsolete,
            "An obsolete date-time format. Replaced by DateAndTime from SNMPv2-TC.",
            rfc,
        ),
        make_type_def(
            "ObjectSyntax",
            ir::TypeSyntax::TypeRef {
                name: "SimpleSyntax".into(),
                span: Span::SYNTHETIC,
            },
            None,
            Status::Current,
            "The union of all SMIv2 data types that may be used in OBJECT-TYPE definitions.",
            rfc,
        ),
        make_type_def(
            "SimpleSyntax",
            ir::TypeSyntax::TypeRef {
                name: "INTEGER".into(),
                span: Span::SYNTHETIC,
            },
            None,
            Status::Current,
            "The union of primitive ASN.1 types: INTEGER, OCTET STRING, and OBJECT IDENTIFIER.",
            rfc,
        ),
        make_type_def(
            "ApplicationSyntax",
            ir::TypeSyntax::TypeRef {
                name: "IpAddress".into(),
                span: Span::SYNTHETIC,
            },
            None,
            Status::Current,
            "The union of application-wide types: IpAddress, Counter32, Gauge32, Unsigned32, TimeTicks, Opaque, and Counter64.",
            rfc,
        ),
    ]
}

fn create_smiv1_type_definitions() -> Vec<ir::Definition> {
    let uint32_max = u64::from(u32::MAX);
    let rfc = "RFC 1155, Section 3.2.3";

    vec![
        make_type_def(
            "Counter",
            constrained_uint_range(uint32_max),
            Some(BaseType::Counter32),
            Status::Current,
            "A non-negative 32-bit counter that monotonically increases until it wraps at 2^32-1. The SMIv1 equivalent of Counter32.",
            &format!("{}.3", rfc),
        ),
        make_type_def(
            "Gauge",
            constrained_uint_range(uint32_max),
            Some(BaseType::Gauge32),
            Status::Current,
            "A non-negative 32-bit integer that may increase or decrease but latches at a maximum value. The SMIv1 equivalent of Gauge32.",
            &format!("{}.4", rfc),
        ),
        make_type_def(
            "IpAddress",
            constrained_octet_fixed(4),
            Some(BaseType::IpAddress),
            Status::Current,
            "An IPv4 address represented as a 4-byte OCTET STRING in network byte order.",
            &format!("{}.1", rfc),
        ),
        make_type_def(
            "NetworkAddress",
            ir::TypeSyntax::TypeRef {
                name: "IpAddress".into(),
                span: Span::SYNTHETIC,
            },
            Some(BaseType::IpAddress),
            Status::Current,
            "A network address from one of possibly several protocol families. In practice, only the internet family (IpAddress) is used.",
            &format!("{}.1", rfc),
        ),
        make_type_def(
            "TimeTicks",
            constrained_uint_range(uint32_max),
            Some(BaseType::TimeTicks),
            Status::Current,
            "A non-negative 32-bit integer representing time in hundredths of a second since some reference epoch.",
            &format!("{}.5", rfc),
        ),
        make_type_def(
            "Opaque",
            ir::TypeSyntax::OctetString,
            Some(BaseType::Opaque),
            Status::Current,
            "An arbitrary ASN.1 value encoded as an OCTET STRING for transparent transport.",
            &format!("{}.6", rfc),
        ),
        make_type_def(
            "ObjectName",
            ir::TypeSyntax::ObjectIdentifier,
            None,
            Status::Current,
            "An OBJECT IDENTIFIER value that names a managed object.",
            "RFC 1155, Section 3.2",
        ),
    ]
}

fn create_tc_definitions() -> Vec<ir::Definition> {
    let int32_max = i64::from(i32::MAX);

    vec![
        make_tc(
            "DisplayString",
            "255a",
            constrained_octet_range(0, 255),
            Status::Current,
            "An NVT ASCII string of 0 to 255 characters. Preferred over the deprecated RFC 1213 DisplayString.",
        ),
        make_tc(
            "PhysAddress",
            "1x:",
            ir::TypeSyntax::OctetString,
            Status::Current,
            "A media- or physical-level address, represented as an OCTET STRING.",
        ),
        make_tc(
            "MacAddress",
            "1x:",
            constrained_octet_fixed(6),
            Status::Current,
            "An IEEE 802 MAC address represented as a 6-byte OCTET STRING in canonical order.",
        ),
        make_tc(
            "TruthValue",
            "",
            integer_enum(vec![nn("true", 1), nn("false", 2)]),
            Status::Current,
            "A boolean value: true(1) or false(2).",
        ),
        make_tc(
            "RowStatus",
            "",
            integer_enum(vec![
                nn("active", 1),
                nn("notInService", 2),
                nn("notReady", 3),
                nn("createAndGo", 4),
                nn("createAndWait", 5),
                nn("destroy", 6),
            ]),
            Status::Current,
            "Controls creation, deletion, and activation of conceptual rows. Values: active(1), notInService(2), notReady(3), createAndGo(4), createAndWait(5), destroy(6).",
        ),
        make_tc(
            "StorageType",
            "",
            integer_enum(vec![
                nn("other", 1),
                nn("volatile", 2),
                nn("nonVolatile", 3),
                nn("permanent", 4),
                nn("readOnly", 5),
            ]),
            Status::Current,
            "Describes the storage persistence of a conceptual row. Values: other(1), volatile(2), nonVolatile(3), permanent(4), readOnly(5).",
        ),
        make_tc(
            "TimeStamp",
            "",
            ir::TypeSyntax::TypeRef {
                name: "TimeTicks".into(),
                span: Span::SYNTHETIC,
            },
            Status::Current,
            "The value of sysUpTime at which a specific occurrence happened. Used to facilitate delta calculations.",
        ),
        make_tc(
            "TimeInterval",
            "",
            constrained_int_range(ir::RangeValue::Signed(0), ir::RangeValue::Signed(int32_max)),
            Status::Current,
            "A period of time measured in hundredths of a second, ranging from 0 to 2147483647.",
        ),
        make_tc(
            "DateAndTime",
            "2d-1d-1d,1d:1d:1d.1d,1a1d:1d",
            constrained_octet_size(vec![
                ir::Range {
                    min: ir::RangeValue::Unsigned(8),
                    max: None,
                    span: Span::SYNTHETIC,
                },
                ir::Range {
                    min: ir::RangeValue::Unsigned(11),
                    max: None,
                    span: Span::SYNTHETIC,
                },
            ]),
            Status::Current,
            "A date-time specification. 8 bytes for local time, 11 bytes when UTC offset is included.",
        ),
        make_tc(
            "TestAndIncr",
            "",
            constrained_int_range(ir::RangeValue::Signed(0), ir::RangeValue::Signed(int32_max)),
            Status::Current,
            "A test-and-increment spinlock. Used for cooperating command generator applications to coordinate SET operations.",
        ),
        make_tc(
            "AutonomousType",
            "",
            ir::TypeSyntax::ObjectIdentifier,
            Status::Current,
            "An OID that identifies a type or protocol independently of the place where it is defined.",
        ),
        make_tc(
            "InstancePointer",
            "",
            ir::TypeSyntax::ObjectIdentifier,
            Status::Obsolete,
            "Obsolete. A pointer to a specific row in a conceptual table. Use VariablePointer instead.",
        ),
        make_tc(
            "VariablePointer",
            "",
            ir::TypeSyntax::ObjectIdentifier,
            Status::Current,
            "A pointer to a specific object instance, including its index. The OID must have an instance suffix.",
        ),
        make_tc(
            "RowPointer",
            "",
            ir::TypeSyntax::ObjectIdentifier,
            Status::Current,
            "A pointer to a conceptual row. The OID is the first accessible columnar object followed by the row's index values.",
        ),
        make_tc(
            "TDomain",
            "",
            ir::TypeSyntax::ObjectIdentifier,
            Status::Current,
            "An OID identifying a transport domain (e.g., snmpUDPDomain for SNMP over UDP/IPv4).",
        ),
        make_tc(
            "TAddress",
            "",
            constrained_octet_range(1, 255),
            Status::Current,
            "A transport address, whose format is defined by the associated TDomain value.",
        ),
    ]
}
