use std::collections::HashSet;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::source::{self, Source};

/// Discover MIB directories from net-snmp and libsmi configuration,
/// deduplicated and filtered to directories that exist.
pub fn discover_system_paths() -> Vec<String> {
    let mut all = discover_netsnmp_paths();
    all.extend(discover_libsmi_paths());
    filter_existing_dirs(dedup(all))
}

/// Create Source instances for all discovered system MIB directories.
pub fn discover_system_sources() -> Vec<Box<dyn Source>> {
    let dirs = discover_system_paths();
    let mut sources = Vec::new();
    for d in dirs {
        match source::dir_source(&d) {
            Ok(src) => sources.push(src),
            Err(e) => debug!(path = %d, error = %e, "skipping system path"),
        }
    }
    sources
}

#[derive(Clone, Copy)]
enum PathOp {
    Replace,
    Append,
    Prepend,
}

type ConfigLineParser = fn(&str) -> Option<(PathOp, Vec<String>)>;

fn discover_netsnmp_paths() -> Vec<String> {
    let mut paths = netsnmp_defaults();
    for cf in netsnmp_config_files() {
        paths = apply_config_file(&cf, paths, parse_netsnmp_line);
    }
    if let Ok(v) = std::env::var("MIBDIRS")
        && !v.is_empty() {
            paths = apply_netsnmp_env(&v, paths);
        }
    paths
}

fn discover_libsmi_paths() -> Vec<String> {
    let mut paths = libsmi_defaults();
    for cf in libsmi_config_files() {
        paths = apply_config_file(&cf, paths, parse_libsmi_line);
    }
    if let Ok(v) = std::env::var("SMIPATH")
        && !v.is_empty() {
            paths = apply_libsmi_env(&v, paths);
        }
    paths
}

fn netsnmp_defaults() -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(home) = dirs::home_dir() {
        paths.push(
            home.join(".snmp")
                .join("mibs")
                .to_string_lossy()
                .to_string(),
        );
    }
    paths.extend([
        "/usr/share/snmp/mibs".to_string(),
        "/usr/share/snmp/mibs/iana".to_string(),
        "/usr/share/snmp/mibs/ietf".to_string(),
        "/usr/local/share/snmp/mibs".to_string(),
    ]);
    paths
}

fn libsmi_defaults() -> Vec<String> {
    vec![
        "/usr/share/mibs/ietf".to_string(),
        "/usr/share/mibs/iana".to_string(),
        "/usr/share/mibs/irtf".to_string(),
        "/usr/share/mibs/site".to_string(),
        "/usr/local/share/mibs/ietf".to_string(),
        "/usr/local/share/mibs/iana".to_string(),
        "/usr/local/share/mibs/irtf".to_string(),
        "/usr/local/share/mibs/site".to_string(),
    ]
}

fn netsnmp_config_files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/snmp/snmp.conf")];
    if let Some(home) = dirs::home_dir() {
        files.push(home.join(".snmp").join("snmp.conf"));
    }
    files
}

fn libsmi_config_files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/smi.conf")];
    if let Some(home) = dirs::home_dir() {
        files.push(home.join(".smirc"));
    }
    files
}

fn parse_netsnmp_line(line: &str) -> Option<(PathOp, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut parts = line.split_whitespace();
    let directive = parts.next()?;
    let value = parts.next()?;

    match directive {
        "mibdirs" => {
            if let Some(rest) = value.strip_prefix('+') {
                Some((PathOp::Append, split_paths(rest)))
            } else if let Some(rest) = value.strip_prefix('-') {
                Some((PathOp::Prepend, split_paths(rest)))
            } else {
                Some((PathOp::Replace, split_paths(value)))
            }
        }
        "+mibdirs" => Some((PathOp::Append, split_paths(value))),
        "-mibdirs" => Some((PathOp::Prepend, split_paths(value))),
        _ => None,
    }
}

fn parse_libsmi_line(line: &str) -> Option<(PathOp, Vec<String>)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    let mut parts = line.split_whitespace();
    let directive = parts.next()?;

    // Skip tagged lines (e.g., "smilint: path ...")
    if directive.ends_with(':') {
        return None;
    }
    if directive != "path" {
        return None;
    }

    let value = parts.next()?;
    let (op, dirs) = parse_colon_semantic(value);
    Some((op, dirs))
}

/// Interpret leading/trailing path-separator semantics used by libsmi.
/// Leading separator = append, trailing separator = prepend, neither = replace.
fn parse_colon_semantic(value: &str) -> (PathOp, Vec<String>) {
    // On Unix the path list separator is ':'
    let list_sep = if cfg!(windows) { ';' } else { ':' };

    if let Some(after) = value.strip_prefix(list_sep) {
        (PathOp::Append, split_paths(after))
    } else if let Some(before) = value.strip_suffix(list_sep) {
        (PathOp::Prepend, split_paths(before))
    } else {
        (PathOp::Replace, split_paths(value))
    }
}

fn apply_netsnmp_env(value: &str, current: Vec<String>) -> Vec<String> {
    if let Some(rest) = value.strip_prefix('+') {
        apply_op(PathOp::Append, split_paths(rest), current)
    } else if let Some(rest) = value.strip_prefix('-') {
        apply_op(PathOp::Prepend, split_paths(rest), current)
    } else {
        split_paths(value)
    }
}

fn apply_libsmi_env(value: &str, current: Vec<String>) -> Vec<String> {
    let (op, dirs) = parse_colon_semantic(value);
    apply_op(op, dirs, current)
}

fn apply_op(op: PathOp, dirs: Vec<String>, mut current: Vec<String>) -> Vec<String> {
    match op {
        PathOp::Append => {
            current.extend(dirs);
            current
        }
        PathOp::Prepend => dirs.into_iter().chain(current).collect(),
        PathOp::Replace => dirs,
    }
}

fn apply_config_file(
    path: &Path,
    mut current: Vec<String>,
    parse_line: ConfigLineParser,
) -> Vec<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return current,
    };

    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                debug!(path = %path.display(), error = %e, "error reading config file");
                break;
            }
        };
        if let Some((op, dirs)) = parse_line(&line) {
            current = apply_op(op, dirs, current);
        }
    }
    current
}

/// Split a path list using the OS path list separator.
fn split_paths(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    let sep = if cfg!(windows) { ';' } else { ':' };
    s.split(sep)
        .filter(|p| !p.is_empty())
        .map(|p| p.to_string())
        .collect()
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for item in items {
        if seen.insert(item.clone()) {
            result.push(item);
        }
    }
    result
}

fn filter_existing_dirs(paths: Vec<String>) -> Vec<String> {
    paths
        .into_iter()
        .filter(|p| std::fs::metadata(p).map(|m| m.is_dir()).unwrap_or(false))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_netsnmp_mibdirs() {
        let (op, dirs) = parse_netsnmp_line("mibdirs /usr/share/snmp/mibs").unwrap();
        assert!(matches!(op, PathOp::Replace));
        assert_eq!(dirs, vec!["/usr/share/snmp/mibs"]);
    }

    #[test]
    fn parse_netsnmp_append() {
        let (op, dirs) = parse_netsnmp_line("mibdirs +/extra/mibs").unwrap();
        assert!(matches!(op, PathOp::Append));
        assert_eq!(dirs, vec!["/extra/mibs"]);
    }

    #[test]
    fn parse_netsnmp_prepend() {
        let (op, dirs) = parse_netsnmp_line("+mibdirs /extra/mibs").unwrap();
        assert!(matches!(op, PathOp::Append));
        assert_eq!(dirs, vec!["/extra/mibs"]);
    }

    #[test]
    fn parse_netsnmp_comment_ignored() {
        assert!(parse_netsnmp_line("# comment").is_none());
    }

    #[test]
    fn parse_libsmi_path() {
        let (op, dirs) = parse_libsmi_line("path /usr/share/mibs/ietf").unwrap();
        assert!(matches!(op, PathOp::Replace));
        assert_eq!(dirs, vec!["/usr/share/mibs/ietf"]);
    }

    #[test]
    fn parse_libsmi_tagged_skipped() {
        assert!(parse_libsmi_line("smilint: path /foo").is_none());
    }

    #[test]
    fn split_paths_basic() {
        let result = split_paths("/a:/b:/c");
        assert_eq!(result, vec!["/a", "/b", "/c"]);
    }

    #[test]
    fn split_paths_empty() {
        assert!(split_paths("").is_empty());
    }

    #[test]
    fn dedup_preserves_order() {
        let result = dedup(vec!["a".into(), "b".into(), "a".into(), "c".into()]);
        assert_eq!(result, vec!["a", "b", "c"]);
    }
}
