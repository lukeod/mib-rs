use std::io::{self, Write};

use mib_rs::writer::{self, Error, Options};
use mib_rs::{DiagnosticConfig, Loader, ModuleIdentityKind, Status, source};
use pretty_assertions::assert_eq;

fn identity_mib() -> mib_rs::Mib {
    Loader::new()
        .source(source::memory(
            "IDENTITY-ONLY-MIB",
            include_bytes!("data/writer-identity-input.mib").as_slice(),
        ))
        .modules(["IDENTITY-ONLY-MIB"])
        .load()
        .expect("identity-only fixture should load")
}

#[test]
fn identity_only_module_matches_golden_output() {
    let mib = identity_mib();

    let mut first = Vec::new();
    writer::write(&mut first, &mib, "IDENTITY-ONLY-MIB").expect("first write should succeed");
    let mut second = Vec::new();
    writer::write(&mut second, &mib, "IDENTITY-ONLY-MIB").expect("second write should succeed");

    assert_eq!(first, second, "repeated writes must be deterministic");
    let output = String::from_utf8(first).expect("writer output should be UTF-8");
    assert_eq!(output, include_str!("data/writer-identity-golden.mib"));

    let reparsed = Loader::new()
        .source(source::memory("IDENTITY-ONLY-MIB", output.as_bytes()))
        .modules(["IDENTITY-ONLY-MIB"])
        .load()
        .expect("golden output should reparse");
    assert_eq!(
        identity_semantics(&mib, "IDENTITY-ONLY-MIB"),
        identity_semantics(&reparsed, "IDENTITY-ONLY-MIB")
    );

    let mut rewritten = Vec::new();
    writer::write(&mut rewritten, &reparsed, "IDENTITY-ONLY-MIB")
        .expect("reparsed module should rewrite");
    assert_eq!(rewritten, output.as_bytes());
}

#[derive(Debug, PartialEq, Eq)]
struct IdentitySemantics {
    name: String,
    kind: ModuleIdentityKind,
    oid: String,
    status: Option<Status>,
    description: String,
    reference: String,
    last_updated: String,
    organization: String,
    contact_info: String,
    revisions: Vec<(String, String)>,
}

fn identity_semantics(mib: &mib_rs::Mib, module_name: &str) -> Vec<IdentitySemantics> {
    let mut identities = mib
        .module(module_name)
        .expect("module should exist")
        .identities()
        .iter()
        .map(|identity| IdentitySemantics {
            name: identity.name().to_owned(),
            kind: identity.kind(),
            oid: identity.oid().to_string(),
            status: identity.status(),
            description: canonical_multiline(identity.description()),
            reference: canonical_multiline(identity.reference()),
            last_updated: identity.last_updated().to_owned(),
            organization: canonical_multiline(identity.organization()),
            contact_info: canonical_multiline(identity.contact_info()),
            revisions: identity
                .revisions()
                .iter()
                .map(|revision| {
                    (
                        revision.date.clone(),
                        canonical_multiline(&revision.description),
                    )
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    identities.sort_by(|left, right| left.name.cmp(&right.name));
    identities
}

fn canonical_multiline(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .enumerate()
        .map(|(index, line)| {
            if index == 0 {
                line
            } else {
                line.trim_start_matches([' ', '\t'])
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn description_option_applies_to_identity_clauses() {
    let mib = identity_mib();
    let mut output = Vec::new();
    writer::write_with_options(
        &mut output,
        &mib,
        "IDENTITY-ONLY-MIB",
        Options::default().with_descriptions(false),
    )
    .expect("write should succeed");

    let output = String::from_utf8(output).expect("writer output should be UTF-8");
    assert!(!output.contains("DESCRIPTION"));
    assert!(output.contains("ORGANIZATION"));
    assert!(output.contains("identityFirst OBJECT-IDENTITY"));
}

#[test]
fn missing_module_is_a_typed_error_and_writes_nothing() {
    let mib = identity_mib();
    let mut output = Vec::new();
    let error = writer::write(&mut output, &mib, "ABSENT-MIB").expect_err("module is absent");

    assert!(matches!(error, Error::ModuleNotFound(name) if name == "ABSENT-MIB"));
    assert!(output.is_empty());
}

#[test]
fn missing_module_preserves_preloaded_destination() {
    let mib = identity_mib();
    let mut output = b"preloaded".to_vec();
    let error = writer::write(&mut output, &mib, "ABSENT-MIB").expect_err("module is absent");

    assert!(matches!(error, Error::ModuleNotFound(_)));
    assert_eq!(output, b"preloaded");
}

struct BrokenWriter;

impl Write for BrokenWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "test failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn destination_failure_is_a_typed_io_error() {
    let mib = identity_mib();
    let error = writer::write(BrokenWriter, &mib, "IDENTITY-ONLY-MIB")
        .expect_err("destination should fail");

    assert!(matches!(error, Error::Io(source) if source.kind() == io::ErrorKind::BrokenPipe));
}

struct FailAfter {
    remaining: usize,
    bytes: Vec<u8>,
}

impl Write for FailAfter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "limit reached"));
        }
        let written = buffer.len().min(self.remaining);
        self.bytes.extend_from_slice(&buffer[..written]);
        self.remaining -= written;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn io_failure_can_leave_a_documented_partial_prefix() {
    let mib = identity_mib();
    let mut destination = FailAfter {
        remaining: 37,
        bytes: Vec::new(),
    };
    let error = writer::write(&mut destination, &mib, "IDENTITY-ONLY-MIB")
        .expect_err("destination should stop mid-module");

    assert!(matches!(error, Error::Io(_)));
    assert_eq!(destination.bytes.len(), 37);
    assert!(include_bytes!("data/writer-identity-golden.mib").starts_with(&destination.bytes));
}

fn load_inline(modules: &[(&str, &str)], requested: &[&str]) -> mib_rs::Mib {
    Loader::new()
        .source(source::memory_modules(modules.iter().map(
            |(name, text)| ((*name).to_owned(), text.as_bytes().to_vec()),
        )))
        .diagnostic_config(DiagnosticConfig::silent())
        .modules(requested.iter().copied())
        .load()
        .expect("inline modules should load")
}

#[test]
fn cross_module_shared_oid_uses_each_exact_declaration() {
    let module_a = r#"COLLISION-A-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
aMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "A"
    CONTACT-INFO "A"
    DESCRIPTION "Module A."
    ::= { enterprises 424260 }
aIdentity OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "Identity A."
    ::= { enterprises 424262 }
END
"#;
    let module_b = r#"COLLISION-B-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
bMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "B"
    CONTACT-INFO "B"
    DESCRIPTION "Module B."
    ::= { enterprises 424261 }
bIdentity OBJECT-IDENTITY
    STATUS deprecated
    DESCRIPTION "Identity B."
    ::= { enterprises 424262 }
END
"#;
    let mib = load_inline(
        &[("COLLISION-A-MIB", module_a), ("COLLISION-B-MIB", module_b)],
        &["COLLISION-A-MIB", "COLLISION-B-MIB"],
    );

    let mut a = Vec::new();
    writer::write(&mut a, &mib, "COLLISION-A-MIB").unwrap();
    let a = String::from_utf8(a).unwrap();
    assert!(a.contains("aIdentity OBJECT-IDENTITY"));
    assert!(a.contains("\"Identity A.\""));
    assert!(!a.contains("bIdentity"));

    let mut b = Vec::new();
    writer::write(&mut b, &mib, "COLLISION-B-MIB").unwrap();
    let b = String::from_utf8(b).unwrap();
    assert!(b.contains("bIdentity OBJECT-IDENTITY"));
    assert!(b.contains("STATUS deprecated"));
    assert!(b.contains("\"Identity B.\""));
    assert!(!b.contains("aIdentity"));
}

#[test]
fn same_module_same_oid_aliases_are_each_emitted_once() {
    let source = r#"ALIAS-MIB DEFINITIONS ::= BEGIN
IMPORTS MODULE-IDENTITY, OBJECT-IDENTITY, enterprises FROM SNMPv2-SMI;
aliasMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Aliases"
    CONTACT-INFO "Aliases"
    DESCRIPTION "Aliases."
    ::= { enterprises 424270 }
aliasOne OBJECT-IDENTITY
    STATUS current
    DESCRIPTION "One."
    ::= { aliasMib 1 }
aliasTwo OBJECT-IDENTITY
    STATUS obsolete
    DESCRIPTION "Two."
    ::= { aliasMib 1 }
END
"#;
    let mib = load_inline(&[("ALIAS-MIB", source)], &["ALIAS-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "ALIAS-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert_eq!(output.matches("aliasOne OBJECT-IDENTITY").count(), 1);
    assert_eq!(output.matches("aliasTwo OBJECT-IDENTITY").count(), 1);
    assert!(output.contains("STATUS current"));
    assert!(output.contains("STATUS obsolete"));
}

#[test]
fn identity_collisions_ignore_winning_object_and_group_metadata() {
    let source = r#"KIND-COLLISION-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI
    OBJECT-GROUP
        FROM SNMPv2-CONF;
collisionMib MODULE-IDENTITY
    LAST-UPDATED "202601010000Z"
    ORGANIZATION "Collisions"
    CONTACT-INFO "Collisions"
    DESCRIPTION "Collisions."
    ::= { enterprises 424280 }
collisionObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Winning object."
    ::= { collisionMib 2 }
objectIdentity OBJECT-IDENTITY
    STATUS deprecated
    DESCRIPTION "Exact object-collision identity."
    ::= { collisionMib 2 }
collisionGroup OBJECT-GROUP
    OBJECTS { collisionObject }
    STATUS current
    DESCRIPTION "Winning group."
    ::= { collisionMib 3 }
groupIdentity OBJECT-IDENTITY
    STATUS obsolete
    DESCRIPTION "Exact group-collision identity."
    ::= { collisionMib 3 }
parentObject OBJECT-TYPE
    SYNTAX Integer32
    MAX-ACCESS not-accessible
    STATUS current
    DESCRIPTION "Unsupported local parent."
    ::= { collisionMib 4 }
childOid OBJECT IDENTIFIER ::= { parentObject 1 }
END
"#;
    let mib = load_inline(&[("KIND-COLLISION-MIB", source)], &["KIND-COLLISION-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "KIND-COLLISION-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("objectIdentity OBJECT-IDENTITY"));
    assert!(output.contains("STATUS deprecated"));
    assert!(output.contains("\"Exact object-collision identity.\""));
    assert!(output.contains("groupIdentity OBJECT-IDENTITY"));
    assert!(output.contains("STATUS obsolete"));
    assert!(output.contains("\"Exact group-collision identity.\""));
    assert!(!output.contains("collisionObject OBJECT-TYPE"));
    assert!(!output.contains("collisionGroup OBJECT-GROUP"));
    assert!(!output.contains("parentObject"));
    assert!(output.contains("childOid OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 424280 4 1 }"));

    let reparsed = load_inline(&[("KIND-COLLISION-MIB", &output)], &["KIND-COLLISION-MIB"]);
    assert_eq!(
        reparsed.resolve_oid("childOid").unwrap().to_string(),
        "1.3.6.1.4.1.424280.4.1"
    );
}

#[test]
fn external_root_parent_is_imported_and_symbolic() {
    let source = r#"ROOT-CHILD-MIB DEFINITIONS ::= BEGIN
rootChild OBJECT IDENTIFIER ::= { iso 9 }
END
"#;
    let mib = load_inline(&[("ROOT-CHILD-MIB", source)], &["ROOT-CHILD-MIB"]);
    let mut output = Vec::new();
    writer::write(&mut output, &mib, "ROOT-CHILD-MIB").unwrap();
    let output = String::from_utf8(output).unwrap();

    assert!(output.contains("iso\n        FROM SNMPv2-SMI;"));
    assert!(output.contains("rootChild OBJECT IDENTIFIER ::= { iso 9 }"));
}
