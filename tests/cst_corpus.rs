mod common;

use std::fmt::Write as _;
use std::path::Path;
use std::sync::Arc;

use mib_rs::compile::{SyntaxKind, parse};
use mib_rs::{SourceCandidate, SourceDocument, SourceOrigin, SourceRange};

use common::{collect_files, corpus_dir};

fn validate_range(
    document: &SourceDocument,
    range: SourceRange,
    path: &Path,
    element: &str,
    index: usize,
    kind: SyntaxKind,
    failures: &mut String,
) -> bool {
    let byte_range = range.byte_range();
    let mut valid = true;
    if range.source() != document.id() {
        valid = false;
        let _ = writeln!(
            failures,
            "{}: {element} {index} ({kind:?}) range belongs to source {}, expected {}",
            path.display(),
            range.source(),
            document.id()
        );
    }
    if byte_range.start > byte_range.end || byte_range.end > document.bytes().len() {
        valid = false;
        let _ = writeln!(
            failures,
            "{}: {element} {index} ({kind:?}) range {}..{} is outside source length {}",
            path.display(),
            byte_range.start,
            byte_range.end,
            document.bytes().len()
        );
    }
    valid
}

fn first_mismatch(actual: &[u8], expected: &[u8]) -> usize {
    actual
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
        .unwrap_or(actual.len().min(expected.len()))
}

#[test]
fn primary_corpus_is_lossless_and_has_valid_ranges() {
    let corpus = corpus_dir();
    assert!(
        corpus.is_dir(),
        "primary corpus directory not found: {}",
        corpus.display()
    );

    let files = collect_files(&corpus);
    assert!(
        !files.is_empty(),
        "no files found in primary corpus: {}",
        corpus.display()
    );

    let mut failures = String::new();
    let mut diagnostic_files = Vec::new();
    let mut diagnostic_count = 0usize;
    let mut node_count = 0usize;
    let mut token_count = 0usize;

    for path in &files {
        let relative = path.strip_prefix(&corpus).unwrap_or(path);
        let source = match std::fs::read(path) {
            Ok(source) => Arc::<[u8]>::from(source),
            Err(error) => {
                let _ = writeln!(failures, "{}: failed to read: {error}", relative.display());
                continue;
            }
        };
        let candidate = SourceCandidate::new(
            relative.to_string_lossy().into_owned(),
            SourceOrigin::file(path),
            relative.to_string_lossy().into_owned(),
            Arc::clone(&source),
        );
        let (tree, diagnostics) = match parse(candidate) {
            Ok(parsed) => parsed,
            Err(error) => {
                let _ = writeln!(failures, "{}: failed to parse: {error}", relative.display());
                continue;
            }
        };

        let file_diagnostics = diagnostics.iter().count();
        if file_diagnostics != 0 {
            diagnostic_count += file_diagnostics;
            diagnostic_files.push((relative.to_path_buf(), file_diagnostics));
        }

        for (index, node) in tree.nodes().enumerate() {
            node_count += 1;
            let _ = validate_range(
                tree.document(),
                node.range(),
                relative,
                "node",
                index,
                node.kind(),
                &mut failures,
            );
        }
        let mut token_ranges_valid = true;
        for (index, token) in tree.tokens().enumerate() {
            token_count += 1;
            let valid = validate_range(
                tree.document(),
                token.range(),
                relative,
                "token",
                index,
                token.kind(),
                &mut failures,
            );
            token_ranges_valid &= valid;
        }

        // Reconstruction slices token ranges, so preserve the range failures
        // and continue to later files instead of panicking on an invalid token.
        if token_ranges_valid {
            let reconstructed = tree.reconstruct_text();
            if reconstructed != source.as_ref() {
                let mismatch = first_mismatch(&reconstructed, &source);
                let _ = writeln!(
                    failures,
                    "{}: reconstruction differs at byte {mismatch} (reconstructed {} bytes, source {} bytes)",
                    relative.display(),
                    reconstructed.len(),
                    source.len()
                );
            }
        }
    }

    assert!(
        failures.is_empty(),
        "CST corpus validation failed:\n{failures}"
    );
    eprintln!(
        "validated {} files, {node_count} nodes, and {token_count} tokens; {diagnostic_count} diagnostics in {} files",
        files.len(),
        diagnostic_files.len()
    );
    for (path, count) in diagnostic_files {
        eprintln!("{}: {count} diagnostics", path.display());
    }
}
