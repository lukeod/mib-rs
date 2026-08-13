use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use mib_rs::source;

use mib_rs::source::{FindResult, Source};
use mib_rs::{DiagCode, DiagnosticConfig, Loader, Severity};

struct AdvertisedSource {
    modules: Vec<String>,
    content: HashMap<String, Vec<u8>>,
    label: &'static str,
}

struct DuplicateCandidateSource {
    name: &'static str,
    candidates: Vec<Vec<u8>>,
    label: &'static str,
}

struct ErrorSource;

struct SharedPathSource;

impl AdvertisedSource {
    fn new(label: &'static str, modules: &[&str], content: &[(&str, &[u8])]) -> Self {
        Self {
            modules: modules.iter().map(|name| (*name).to_string()).collect(),
            content: content
                .iter()
                .map(|(name, bytes)| ((*name).to_string(), bytes.to_vec()))
                .collect(),
            label,
        }
    }
}

impl Source for AdvertisedSource {
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        Ok(self.content.get(name).map(|content| FindResult {
            content: content.clone(),
            path: PathBuf::from(format!("<{}:{name}>", self.label)),
        }))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        Ok(self.modules.clone())
    }
}

impl Source for DuplicateCandidateSource {
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        self.find_candidates(name).next().transpose()
    }

    fn find_candidates<'a>(
        &'a self,
        name: &'a str,
    ) -> Box<dyn Iterator<Item = io::Result<FindResult>> + 'a> {
        Box::new(
            self.candidates
                .iter()
                .filter(move |_| name == self.name)
                .map(move |content| {
                    Ok(FindResult {
                        content: content.clone(),
                        path: PathBuf::from(format!("<{}:{name}>", self.label)),
                    })
                }),
        )
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        Ok(vec![self.name.to_string()])
    }
}

impl Source for ErrorSource {
    fn find(&self, _name: &str) -> io::Result<Option<FindResult>> {
        Err(io::Error::other("lower-priority source accessed"))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        Ok(vec!["REAL-MIB".to_string()])
    }
}

impl Source for SharedPathSource {
    fn find(&self, name: &str) -> io::Result<Option<FindResult>> {
        let content = match name {
            "A-MIB" => b"A-MIB DEFINITIONS ::= BEGIN\nEND\n".as_slice(),
            "B-MIB" => b"B-MIB DEFINITIONS ::= BEGIN\nEND\n".as_slice(),
            _ => return Ok(None),
        };
        Ok(Some(FindResult {
            content: content.to_vec(),
            path: PathBuf::from("<shared>"),
        }))
    }

    fn list_modules(&self) -> io::Result<Vec<String>> {
        Ok(vec!["A-MIB".to_string(), "B-MIB".to_string()])
    }
}

fn permissive_diagnostics() -> DiagnosticConfig {
    let mut config = DiagnosticConfig::verbose();
    config.fail_at = Severity::Fatal;
    config
}

static TEMP_ID: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("mib-rs-source-scanner-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const MALFORMED: &[u8] = b"LEADING-TOKEN REAL-MIB DEFINITIONS ::= BEGIN\nEND\n";
const PHANTOM: &[u8] = b"OTHER-MIB DEFINITIONS ::= BEGIN\nEND\n";
const VALID: &[u8] = b"REAL-MIB DEFINITIONS ::= BEGIN\nEND\n";

fn assert_real_mib_loaded(loader: Loader, expected_path: &Path) {
    let mib = loader
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("valid candidate should load");
    let module = mib.module("REAL-MIB").expect("REAL-MIB should be loaded");
    assert_eq!(module.source_path(), expected_path.to_string_lossy());
}

#[test]
fn file_source_defers_reserved_module_name_to_parser_policy() {
    let dir = TempDir::new();
    let path = dir.path().join("reserved-name.mib");
    std::fs::write(&path, b"TRUE DEFINITIONS ::= BEGIN\nEND\n")
        .expect("write reserved-name module");

    let file = source::file(&path).expect("scanner should retain parser-accepted module name");
    let mib = Loader::new()
        .source(file)
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("permissive parser policy should allow reserved module name");

    assert!(mib.module("TRUE").is_some());
    assert!(
        mib.diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == DiagCode::KeywordReserved),
        "parser should diagnose the reserved module name"
    );
}

#[test]
fn explicit_load_continues_after_phantom_source_candidate() {
    let phantom = AdvertisedSource::new(
        "phantom",
        &["REAL-MIB"],
        &[(
            "REAL-MIB",
            br#"DESCRIPTION "REAL-MIB DEFINITIONS ::= BEGIN"
OTHER-MIB DEFINITIONS ::= BEGIN
END
"#,
        )],
    );
    let valid = AdvertisedSource::new(
        "valid",
        &["REAL-MIB"],
        &[("REAL-MIB", b"REAL-MIB DEFINITIONS ::= BEGIN\nEND\n")],
    );

    let mib = Loader::new()
        .source(Box::new(phantom))
        .source(Box::new(valid))
        .modules(["REAL-MIB"])
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("later valid source should satisfy the requested module");

    let module = mib.module("REAL-MIB").expect("REAL-MIB should be loaded");
    assert_eq!(module.source_path(), "<valid:REAL-MIB>");
}

#[test]
fn explicit_chain_load_continues_after_phantom_child() {
    let phantom = AdvertisedSource::new(
        "phantom",
        &["REAL-MIB"],
        &[("REAL-MIB", b"OTHER-MIB DEFINITIONS ::= BEGIN\nEND\n")],
    );
    let valid = AdvertisedSource::new(
        "valid",
        &["REAL-MIB"],
        &[("REAL-MIB", b"REAL-MIB DEFINITIONS ::= BEGIN\nEND\n")],
    );

    let mib = Loader::new()
        .source(source::chain(vec![Box::new(phantom), Box::new(valid)]))
        .modules(["REAL-MIB"])
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("later valid chain child should satisfy the requested module");

    let module = mib.module("REAL-MIB").expect("REAL-MIB should be loaded");
    assert_eq!(module.source_path(), "<valid:REAL-MIB>");
}

#[test]
fn load_all_chain_continues_after_phantom_child() {
    let phantom = AdvertisedSource::new(
        "phantom",
        &["REAL-MIB"],
        &[("REAL-MIB", b"OTHER-MIB DEFINITIONS ::= BEGIN\nEND\n")],
    );
    let valid = AdvertisedSource::new(
        "valid",
        &["REAL-MIB"],
        &[("REAL-MIB", b"REAL-MIB DEFINITIONS ::= BEGIN\nEND\n")],
    );

    let mib = Loader::new()
        .source(source::chain(vec![Box::new(phantom), Box::new(valid)]))
        .parallelism(2)
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("later valid chain child should win after candidate validation");

    let module = mib.module("REAL-MIB").expect("REAL-MIB should be loaded");
    assert_eq!(module.source_path(), "<valid:REAL-MIB>");
}

#[test]
fn load_all_continues_after_phantom_source_candidate() {
    let phantom = AdvertisedSource::new(
        "phantom",
        &["REAL-MIB"],
        &[(
            "REAL-MIB",
            br#"DESCRIPTION "REAL-MIB DEFINITIONS ::= BEGIN"
OTHER-MIB DEFINITIONS ::= BEGIN
END
"#,
        )],
    );
    let valid = AdvertisedSource::new(
        "valid",
        &["REAL-MIB"],
        &[("REAL-MIB", b"REAL-MIB DEFINITIONS ::= BEGIN\nEND\n")],
    );

    let mib = Loader::new()
        .source(Box::new(phantom))
        .source(Box::new(valid))
        .parallelism(2)
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("later valid source should win after candidate validation");

    let module = mib.module("REAL-MIB").expect("REAL-MIB should be loaded");
    assert_eq!(module.source_path(), "<valid:REAL-MIB>");
    assert!(mib.module("OTHER-MIB").is_none());
}

fn write_malformed_and_valid_files(dir: &TempDir) -> (PathBuf, PathBuf) {
    let malformed = dir.path().join("01-malformed.mib");
    let valid = dir.path().join("02-valid.mib");
    std::fs::write(&malformed, MALFORMED).expect("write malformed candidate");
    std::fs::write(&valid, VALID).expect("write valid candidate");
    (malformed, valid)
}

fn duplicate_candidate_source() -> DuplicateCandidateSource {
    DuplicateCandidateSource {
        name: "REAL-MIB",
        candidates: vec![PHANTOM.to_vec(), VALID.to_vec()],
        label: "duplicate-path",
    }
}

#[test]
fn explicit_load_continues_after_duplicate_source_candidate() {
    let mib = Loader::new()
        .source(Box::new(duplicate_candidate_source()))
        .modules(["REAL-MIB"])
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("later candidate in one source should satisfy the request");

    assert!(mib.module("REAL-MIB").is_some());
}

#[test]
fn load_all_continues_after_duplicate_source_candidate() {
    let mib = Loader::new()
        .source(Box::new(duplicate_candidate_source()))
        .parallelism(2)
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("later candidate in one source should load");

    assert!(mib.module("REAL-MIB").is_some());
}

#[test]
fn built_in_sources_retain_duplicate_candidates_in_order() {
    let dir = TempDir::new();
    let first = dir.path().join("01-first.mib");
    let second = dir.path().join("02-second.mib");
    std::fs::write(&first, VALID).expect("write first candidate");
    std::fs::write(&second, VALID).expect("write second candidate");

    let files = source::files([first.clone(), second.clone()]).expect("build file source");
    let file_candidates = files
        .find_candidates("REAL-MIB")
        .collect::<io::Result<Vec<_>>>()
        .expect("find file candidates");
    assert_eq!(
        file_candidates
            .iter()
            .map(|candidate| candidate.path.as_path())
            .collect::<Vec<_>>(),
        vec![first.as_path(), second.as_path()]
    );

    let directory = source::dir(dir.path()).expect("build directory source");
    let directory_candidates = directory
        .find_candidates("REAL-MIB")
        .collect::<io::Result<Vec<_>>>()
        .expect("find directory candidates");
    assert_eq!(directory_candidates.len(), 2);
    let directory_paths = directory_candidates
        .iter()
        .map(|candidate| candidate.path.as_path())
        .collect::<Vec<_>>();
    assert!(directory_paths.contains(&first.as_path()));
    assert!(directory_paths.contains(&second.as_path()));
}

#[test]
fn explicit_files_load_skips_malformed_first_path() {
    let dir = TempDir::new();
    let (malformed, valid) = write_malformed_and_valid_files(&dir);
    let files = source::files([malformed, valid.clone()]).expect("build file source");

    assert_real_mib_loaded(Loader::new().source(files).modules(["REAL-MIB"]), &valid);
}

#[test]
fn load_all_files_skips_malformed_first_path() {
    let dir = TempDir::new();
    let (malformed, valid) = write_malformed_and_valid_files(&dir);
    let files = source::files([malformed, valid.clone()]).expect("build file source");

    assert_real_mib_loaded(Loader::new().source(files).parallelism(2), &valid);
}

#[test]
fn explicit_directory_load_skips_malformed_first_path() {
    let dir = TempDir::new();
    let (_, valid) = write_malformed_and_valid_files(&dir);
    let directory = source::dir(dir.path()).expect("build directory source");

    assert_real_mib_loaded(
        Loader::new().source(directory).modules(["REAL-MIB"]),
        &valid,
    );
}

#[test]
fn load_all_directory_skips_malformed_first_path() {
    let dir = TempDir::new();
    let (_, valid) = write_malformed_and_valid_files(&dir);
    let directory = source::dir(dir.path()).expect("build directory source");

    assert_real_mib_loaded(Loader::new().source(directory).parallelism(2), &valid);
}

#[test]
fn chained_valid_candidate_stops_before_later_io_error() {
    let valid = AdvertisedSource::new("valid", &["REAL-MIB"], &[("REAL-MIB", VALID)]);
    let chained = source::chain(vec![Box::new(valid), Box::new(ErrorSource)]);

    assert_real_mib_loaded(
        Loader::new().source(chained).modules(["REAL-MIB"]),
        Path::new("<valid:REAL-MIB>"),
    );
}

#[test]
fn load_all_chain_stops_before_later_io_error() {
    let valid = AdvertisedSource::new("valid", &["REAL-MIB"], &[("REAL-MIB", VALID)]);
    let chained = source::chain(vec![Box::new(valid), Box::new(ErrorSource)]);

    assert_real_mib_loaded(
        Loader::new().source(chained).parallelism(1),
        Path::new("<valid:REAL-MIB>"),
    );
}

fn directory_with_later_stale_candidate(dir: &TempDir) -> (Box<dyn Source>, PathBuf) {
    let first = dir.path().join("01-first.mib");
    let second = dir.path().join("02-second.mib");
    std::fs::write(&first, VALID).expect("write first candidate");
    std::fs::write(&second, VALID).expect("write second candidate");
    let directory = source::dir(dir.path()).expect("build directory source");

    let candidate_paths = directory
        .find_candidates("REAL-MIB")
        .collect::<io::Result<Vec<_>>>()
        .expect("inspect indexed candidate order")
        .into_iter()
        .map(|candidate| candidate.path)
        .collect::<Vec<_>>();
    assert_eq!(candidate_paths.len(), 2);
    std::fs::remove_file(&candidate_paths[1]).expect("make later index entry stale");
    (directory, candidate_paths[0].clone())
}

#[test]
fn directory_valid_candidate_stops_before_later_stale_path() {
    let dir = TempDir::new();
    let (directory, valid_path) = directory_with_later_stale_candidate(&dir);

    assert_real_mib_loaded(
        Loader::new().source(directory).modules(["REAL-MIB"]),
        &valid_path,
    );
}

#[test]
fn load_all_directory_stops_before_later_stale_path() {
    let dir = TempDir::new();
    let (directory, valid_path) = directory_with_later_stale_candidate(&dir);

    assert_real_mib_loaded(Loader::new().source(directory).parallelism(1), &valid_path);
}

#[test]
fn explicit_load_cache_distinguishes_module_names_with_same_path() {
    let mib = Loader::new()
        .source(Box::new(SharedPathSource))
        .modules(["A-MIB", "B-MIB"])
        .parallelism(1)
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("both same-path candidates should decode independently");

    assert!(mib.module("A-MIB").is_some());
    assert!(mib.module("B-MIB").is_some());
}

#[test]
fn load_all_cache_distinguishes_module_names_with_same_path() {
    let mib = Loader::new()
        .source(Box::new(SharedPathSource))
        .parallelism(1)
        .diagnostic_config(permissive_diagnostics())
        .load()
        .expect("both same-path candidates should decode independently");

    assert!(mib.module("A-MIB").is_some());
    assert!(mib.module("B-MIB").is_some());
}
