//! Lexical tokenization of MIB source text.
//!
//! The token API lets you work with raw MIB syntax without parsing,
//! useful for syntax highlighting, linting, or custom tooling.

use std::sync::Arc;

use mib_rs::token::{self, TokenKind};
use mib_rs::{Diagnostic, SourceDocument, SourceOrigin, SourceSet};

fn render(document: &SourceDocument, diagnostic: &Diagnostic) -> String {
    let Some(range) = diagnostic.range else {
        return diagnostic.to_string();
    };
    if let Err(error) = document.slice(range) {
        return format!("{diagnostic} [location unavailable: {error}]");
    }
    let start = match document.byte_position(range.start()) {
        Ok(position) => position,
        Err(error) => return format!("{diagnostic} [location unavailable: {error}]"),
    };
    let end = match document.byte_position(range.end()) {
        Ok(position) => position,
        Err(error) => return format!("{diagnostic} [location unavailable: {error}]"),
    };
    format!(
        "[{}] {}:{}:{}-{}:{}: {}",
        diagnostic.severity,
        document.label(),
        u64::from(start.line()) + 1,
        u64::from(start.column()) + 1,
        u64::from(end.line()) + 1,
        u64::from(end.column()) + 1,
        diagnostic.message
    )
}

fn main() {
    let source = br#"EXAMPLE-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, Integer32, enterprises
        FROM SNMPv2-SMI;

exampleMib MODULE-IDENTITY
    LAST-UPDATED "202603120000Z"
    ORGANIZATION "Example Corp"
    CONTACT-INFO "support@example.com"
    DESCRIPTION "An example."
    ::= { enterprises 99999 }

exValue OBJECT-TYPE
    SYNTAX Integer32 (0..100)
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION "A value."
    ::= { exampleMib 1 }

END
"#;

    let mut sources = SourceSet::new();
    let source_id = sources
        .insert(
            SourceOrigin::memory("tokens-example"),
            "EXAMPLE-MIB",
            Arc::from(source.as_slice()),
        )
        .expect("example source should fit the compiler coordinate space");
    let document = sources
        .get(source_id)
        .expect("the example source was just inserted");

    // -- Tokenize --
    let (tokens, diagnostics) = token::tokenize(document);

    println!("=== Tokens ({} total) ===", tokens.len());
    for tok in &tokens {
        // Extract the token text from the source bytes.
        let text = std::str::from_utf8(
            document
                .slice(tok.span)
                .expect("tokens belong to the example source document"),
        )
        .unwrap_or("<binary>");

        // Skip comments for brevity.
        if tok.kind == TokenKind::Comment {
            continue;
        }

        let category = classify(tok.kind);
        println!(
            "  {:<24} {:<14} {:?}",
            text,
            tok.kind.libsmi_name(),
            category,
        );

        // Stop at EOF.
        if tok.kind == TokenKind::Eof {
            break;
        }
    }

    // -- Diagnostics from lexing --
    if !diagnostics.is_empty() {
        println!("\nLexer diagnostics:");
        for diagnostic in &diagnostics {
            println!("  {}", render(document, diagnostic));
        }
    } else {
        println!("\nNo lexer diagnostics.");
    }

    // -- Token classification predicates --
    println!("\n=== Token classification ===");
    let interesting = [
        TokenKind::KwDefinitions,
        TokenKind::KwObjectType,
        TokenKind::KwModuleIdentity,
        TokenKind::KwSyntax,
        TokenKind::KwInteger,
        TokenKind::KwReadOnly,
        TokenKind::KwCurrent,
        TokenKind::UppercaseIdent,
        TokenKind::LowercaseIdent,
        TokenKind::Number,
        TokenKind::QuotedString,
        TokenKind::ColonColonEqual,
        TokenKind::LBrace,
    ];

    for kind in interesting {
        println!(
            "  {:<24} keyword={:<5} macro={:<5} clause={:<5} type={:<5} ident={:<5} status/access={}",
            kind.libsmi_name(),
            kind.is_keyword(),
            kind.is_macro_keyword(),
            kind.is_clause_keyword(),
            kind.is_type_keyword(),
            kind.is_identifier(),
            kind.is_status_access_keyword(),
        );
    }

    // -- Display names (human-readable for error messages) --
    println!("\n=== Display names ===");
    for kind in [
        TokenKind::LBrace,
        TokenKind::ColonColonEqual,
        TokenKind::KwObjectType,
        TokenKind::UppercaseIdent,
        TokenKind::Number,
        TokenKind::Eof,
    ] {
        println!(
            "  {:<24} display={:?}  libsmi={:?}",
            format!("{kind:?}"),
            kind.display_name(),
            kind.libsmi_name(),
        );
    }

    // -- Count tokens by category --
    println!("\n=== Token statistics ===");
    let mut keywords = 0;
    let mut identifiers = 0;
    let mut literals = 0;
    let mut punctuation = 0;
    let mut other = 0;

    for tok in &tokens {
        if tok.kind == TokenKind::Eof || tok.kind == TokenKind::Comment {
            continue;
        }
        match classify(tok.kind) {
            "keyword" => keywords += 1,
            "identifier" => identifiers += 1,
            "literal" => literals += 1,
            "punctuation" => punctuation += 1,
            _ => other += 1,
        }
    }

    println!("  Keywords:    {keywords}");
    println!("  Identifiers: {identifiers}");
    println!("  Literals:    {literals}");
    println!("  Punctuation: {punctuation}");
    println!("  Other:       {other}");
}

fn classify(kind: TokenKind) -> &'static str {
    if kind.is_keyword() {
        "keyword"
    } else if kind.is_identifier() {
        "identifier"
    } else if matches!(
        kind,
        TokenKind::Number
            | TokenKind::NegativeNumber
            | TokenKind::QuotedString
            | TokenKind::HexString
            | TokenKind::BinString
    ) {
        "literal"
    } else if matches!(
        kind,
        TokenKind::LBrace
            | TokenKind::RBrace
            | TokenKind::LParen
            | TokenKind::RParen
            | TokenKind::LBracket
            | TokenKind::RBracket
            | TokenKind::Comma
            | TokenKind::Semicolon
            | TokenKind::Colon
            | TokenKind::Dot
            | TokenKind::DotDot
            | TokenKind::Pipe
            | TokenKind::Minus
            | TokenKind::ColonColonEqual
    ) {
        "punctuation"
    } else {
        "other"
    }
}
