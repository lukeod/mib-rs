use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

#[allow(dead_code)]
pub fn problems_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/problems")
}

#[allow(dead_code)]
pub fn collect_mib_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some("mib" | "smi" | "txt" | "my") = path.extension().and_then(|e| e.to_str()) {
            files.push(path.to_path_buf());
        }
    }
    files
}
