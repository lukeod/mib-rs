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
pub struct IndexInfo {
    pub name: String,
    pub implied: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct RangeInfo {
    pub low: i64,
    pub high: i64,
}
