use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

use mib_rs::types::{DiagnosticConfig, ResolverStrictness};
use mib_rs::{Loader, Source, SourceCandidate, SourceOrigin, load};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::{LookupSpan, Registry};

#[derive(Clone, Debug)]
struct RecordedSpan {
    target: String,
    name: String,
    fields: String,
}

#[derive(Clone, Debug)]
struct RecordedEvent {
    target: String,
    fields: String,
}

#[derive(Clone, Default)]
struct Capture {
    spans: Arc<Mutex<Vec<RecordedSpan>>>,
    events: Arc<Mutex<Vec<RecordedEvent>>>,
}

impl Capture {
    fn spans(&self) -> Vec<RecordedSpan> {
        self.spans.lock().unwrap().clone()
    }

    fn events(&self) -> Vec<RecordedEvent> {
        self.events.lock().unwrap().clone()
    }
}

struct CaptureLayer {
    capture: Capture,
}

impl CaptureLayer {
    fn new(capture: Capture) -> Self {
        Self { capture }
    }
}

impl<S> Layer<S> for CaptureLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        attrs.record(&mut visitor);
        self.capture.spans.lock().unwrap().push(RecordedSpan {
            target: attrs.metadata().target().to_string(),
            name: attrs.metadata().name().to_string(),
            fields: visitor.finish(),
        });
    }

    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);
        self.capture.events.lock().unwrap().push(RecordedEvent {
            target: event.metadata().target().to_string(),
            fields: visitor.finish(),
        });
    }
}

#[derive(Default)]
struct FieldVisitor {
    fields: Vec<String>,
}

impl FieldVisitor {
    fn finish(mut self) -> String {
        self.fields.sort();
        self.fields.join(" ")
    }
}

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.fields.push(format!("{}={value:?}", field.name()));
    }
}

struct MemorySource {
    modules: HashMap<String, &'static str>,
}

impl Source for MemorySource {
    fn find(&self, name: &str) -> io::Result<Option<SourceCandidate>> {
        Ok(self.modules.get(name).map(|content| {
            SourceCandidate::new(
                name,
                SourceOrigin::memory(name),
                format!("memory:{name}"),
                content.as_bytes(),
            )
        }))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        let mut modules: Vec<_> = self.modules.keys().cloned().collect();
        modules.sort();
        Ok(modules)
    }
}

#[test]
fn load_emits_lowering_spans_and_events() {
    let source = MemorySource {
        modules: HashMap::from([(
            "TEST-MIB".to_string(),
            r#"TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, enterprises FROM SNMPv2-SMI
    DisplayString FROM SNMPv2-TC;

testMib MODULE-IDENTITY
    LAST-UPDATED "202603100000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example"
    ::= { enterprises 99999 }

testObject OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Example"
    ::= { testMib 1 }

END
"#,
        )]),
    };

    let capture = Capture::default();
    let subscriber = Registry::default().with(CaptureLayer::new(capture.clone()));

    tracing::subscriber::with_default(subscriber, || {
        let options = Loader::new()
            .source(Box::new(source))
            .modules(["TEST-MIB"])
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent());
        let result = load(options).expect("load should succeed");
        assert!(result.module_by_name("TEST-MIB").is_some());
    });

    let spans = capture.spans();
    assert!(spans.iter().any(|span| {
        span.target == "mib_rs::lower"
            && span.name == "lower"
            && span.fields.contains(r#"module=TEST-MIB"#)
            && span.fields.contains(r#"definition_count=2"#)
    }));
    assert!(spans.iter().any(|span| {
        span.target == "mib_rs::lower"
            && span.name == "phase"
            && span.fields.contains(r#"phase="definitions""#)
    }));

    let events = capture.events();
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::lower"
            && event.fields.contains(r#"message=starting phase"#)
            && event.fields.contains(r#"component="lower""#)
            && event.fields.contains(r#"phase="imports""#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::lower"
            && event.fields.contains(r#"message=lower complete"#)
            && event.fields.contains(r#"diagnostic_count=0"#)
            && event.fields.contains(r#"definition_count=2"#)
            && event.fields.contains(r#"module=TEST-MIB"#)
    }));
}

#[test]
fn load_emits_normalized_load_parser_and_resolver_fields() {
    let source = MemorySource {
        modules: HashMap::from([(
            "TEST-MIB".to_string(),
            r#"TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, enterprises FROM SNMPv2-SMI
    DisplayString FROM SNMPv2-TC;

testMib MODULE-IDENTITY
    LAST-UPDATED "202603100000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example"
    ::= { enterprises 99999 }

testObject OBJECT-TYPE
    SYNTAX DisplayString
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Example"
    ::= { testMib 1 }

END
"#,
        )]),
    };

    let capture = Capture::default();
    let subscriber = Registry::default().with(CaptureLayer::new(capture.clone()));

    tracing::subscriber::with_default(subscriber, || {
        let options = Loader::new()
            .source(Box::new(source))
            .modules(["TEST-MIB"])
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent());
        let result = load(options).expect("load should succeed");
        assert!(result.module_by_name("TEST-MIB").is_some());
    });

    let spans = capture.spans();
    assert!(spans.iter().any(|span| {
        span.target == "mib_rs::load"
            && span.name == "load"
            && span.fields.contains(r#"component="load""#)
            && span.fields.contains(r#"explicit_source_count=1"#)
            && span.fields.contains(r#"requested_module_count=1"#)
    }));
    assert!(spans.iter().any(|span| {
        span.target == "mib_rs::parser"
            && span.name == "parse"
            && span.fields.contains(r#"byte_count="#)
            && span.fields.contains(r#"component="parser""#)
    }));
    assert!(spans.iter().any(|span| {
        span.target == "mib_rs::resolver"
            && span.name == "resolve"
            && span.fields.contains(r#"component="resolver""#)
            && span.fields.contains(r#"module_count="#)
    }));

    let events = capture.events();
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::parser"
            && event.fields.contains(r#"message=parse complete"#)
            && event.fields.contains(r#"component="parser""#)
            && event.fields.contains(r#"module_count=1"#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::resolver"
            && event.fields.contains(r#"message=phase complete"#)
            && event.fields.contains(r#"component="resolver""#)
            && event.fields.contains(r#"phase="types""#)
            && event.fields.contains(r#"type_count="#)
            && event.fields.contains(r#"unresolved_type_count=0"#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::resolver"
            && event.fields.contains(r#"message=created resolved objects"#)
            && event.fields.contains(r#"component="resolver""#)
            && event.fields.contains(r#"phase="semantics""#)
            && event.fields.contains(r#"object_count=1"#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::resolver"
            && event
                .fields
                .contains(r#"message=classified object node kinds"#)
            && event.fields.contains(r#"component="resolver""#)
            && event.fields.contains(r#"phase="semantics""#)
            && event.fields.contains(r#"scalar_count=1"#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::load"
            && event.fields.contains(r#"message=load complete"#)
            && event.fields.contains(r#"component="load""#)
            && event.fields.contains(r#"module_count="#)
            && event.fields.contains(r#"type_count="#)
    }));
}

#[test]
fn load_emits_resolver_trace_events_for_unresolved_imports_and_oid_fallbacks() {
    let source = MemorySource {
        modules: HashMap::from([(
            "TRACE-TEST-MIB".to_string(),
            r#"TRACE-TEST-MIB DEFINITIONS ::= BEGIN
IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE FROM SNMPv2-SMI
    MissingType FROM MISSING-MIB;

traceTest MODULE-IDENTITY
    LAST-UPDATED "202603100000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "Example"
    DESCRIPTION "Example"
    ::= { enterprises 99998 }

traceObject OBJECT-TYPE
    SYNTAX OCTET STRING
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "Example"
    ::= { traceTest 1 }

END
"#,
        )]),
    };

    let capture = Capture::default();
    let subscriber = Registry::default().with(CaptureLayer::new(capture.clone()));

    tracing::subscriber::with_default(subscriber, || {
        let options = Loader::new()
            .source(Box::new(source))
            .modules(["TRACE-TEST-MIB"])
            .resolver_strictness(ResolverStrictness::Permissive)
            .diagnostic_config(DiagnosticConfig::silent());
        let result = load(options).expect("load should succeed");
        assert!(result.module_by_name("TRACE-TEST-MIB").is_some());
    });

    let events = capture.events();
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::resolver"
            && event
                .fields
                .contains(r#"message=failed to resolve import group"#)
            && event.fields.contains(r#"component="resolver""#)
            && event.fields.contains(r#"phase="imports""#)
            && event.fields.contains(r#"module=TRACE-TEST-MIB"#)
            && event.fields.contains(r#"reason="module_not_found""#)
            && event.fields.contains(r#"resolution="unresolved""#)
            && event.fields.contains(r#"source_module=MISSING-MIB"#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::resolver"
            && event
                .fields
                .contains(r#"message=resolved oid graph edge via constrained fallback"#)
            && event.fields.contains(r#"component="resolver""#)
            && event
                .fields
                .contains(r#"fallback="smi_global_root_graph_edge""#)
            && event.fields.contains(r#"module=TRACE-TEST-MIB"#)
            && event.fields.contains(r#"name=enterprises"#)
            && event.fields.contains(r#"phase="oids""#)
    }));
    assert!(events.iter().any(|event| {
        event.target == "mib_rs::resolver"
            && event
                .fields
                .contains(r#"message=resolved oid name via constrained fallback"#)
            && event.fields.contains(r#"component="resolver""#)
            && event.fields.contains(r#"fallback="smi_global_root""#)
            && event.fields.contains(r#"module=TRACE-TEST-MIB"#)
            && event.fields.contains(r#"name=enterprises"#)
            && event.fields.contains(r#"phase="oids""#)
    }));
}
