use std::path::{Path, PathBuf};

use serde::Deserialize;

#[allow(dead_code)]
pub fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/primary")
}

#[allow(dead_code)]
pub fn problems_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/corpus/problems")
}

#[allow(dead_code)]
pub fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(dir) {
        let entry = entry.unwrap_or_else(|error| {
            panic!(
                "failed to enumerate corpus beneath {}: {error}",
                dir.display()
            )
        });
        if entry.file_type().is_file() {
            files.push(entry.into_path());
        }
    }
    files.sort();
    files
}

#[allow(dead_code)]
pub fn collect_mib_files(dir: &Path) -> Vec<PathBuf> {
    collect_files(dir)
        .into_iter()
        .filter(|path| {
            matches!(
                path.extension().and_then(|extension| extension.to_str()),
                Some("mib" | "smi" | "txt" | "my")
            )
        })
        .collect()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[serde(bound(deserialize = "C: Deserialize<'de>, S: Deserialize<'de>"))]
#[allow(dead_code)]
pub struct FixtureNode<C = serde::de::IgnoredAny, S = serde::de::IgnoredAny> {
    #[serde(rename = "OID")]
    pub oid: String,
    pub name: String,
    pub module: String,
    #[serde(default)]
    pub description: String,
    #[serde(rename = "Type")]
    pub typ: String,
    pub access: String,
    pub status: String,
    pub hint: String,
    #[serde(rename = "TCName")]
    pub tc_name: String,
    pub units: String,
    #[serde(default)]
    pub enum_values: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub indexes: Option<Vec<IndexInfo>>,
    pub augments: String,
    #[serde(default)]
    pub ranges: Option<Vec<RangeInfo>>,
    #[serde(default)]
    pub default_value: String,
    pub kind: String,
    #[serde(default)]
    pub varbinds: Option<Vec<String>>,
    #[serde(default)]
    pub group_members: Option<Vec<String>>,
    pub node_type: String,
    #[serde(default)]
    pub bit_values: std::collections::HashMap<String, String>,
    pub reference: String,
    #[serde(default)]
    pub product_release: String,
    #[serde(rename = "ComplianceModules", default)]
    pub compliance_modules: Vec<C>,
    #[serde(rename = "CapabilitySupports", default)]
    pub capability_supports: Vec<S>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub struct IndexInfo {
    pub name: String,
    pub implied: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
#[allow(dead_code)]
pub struct RangeInfo {
    pub low: i64,
    pub high: i64,
}
