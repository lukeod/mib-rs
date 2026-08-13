//! System MIB path discovery for net-snmp and libsmi.
//!
//! Probes standard config files (`/etc/snmp/snmp.conf`, `~/.snmp/snmp.conf`,
//! `/etc/smi.conf`, `~/.smirc`) and environment variables (`MIBDIRS`,
//! `SMIPATH`) to locate MIB directories installed on the system.
//!
//! Typically used via [`Loader::system_paths`](crate::Loader::system_paths)
//! rather than called directly.

use std::collections::HashSet;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use tracing::debug;

use crate::source::{self, Source};

/// Discover MIB directories from net-snmp and libsmi configuration.
///
/// Reads config files and environment variables, deduplicates paths, and
/// filters to directories that actually exist on disk. Literal `$HOME`
/// occurrences in net-snmp paths are expanded using the user's home directory.
///
/// Checked sources (in order):
/// - net-snmp defaults (`~/.snmp/mibs`, `/usr/share/snmp/mibs`, etc.)
/// - `/etc/snmp/snmp.conf` and `~/.snmp/snmp.conf` (`mibdirs` directive)
/// - `MIBDIRS` environment variable
/// - libsmi defaults (`/usr/share/mibs/ietf`, etc.)
/// - `/etc/smi.conf` and `~/.smirc` (`path` directive)
/// - `SMIPATH` environment variable
pub fn discover_system_paths() -> Vec<String> {
    let mut all = discover_netsnmp_paths();
    all.extend(discover_libsmi_paths());
    filter_existing_dirs(dedup(all))
}

/// Create [`Source`] instances for all discovered system MIB directories.
///
/// Calls [`discover_system_paths`] and wraps each directory with
/// [`source::dir`]. Directories that fail to index
/// are silently skipped (logged at debug level).
pub fn discover_system_sources() -> Vec<Box<dyn Source>> {
    let dirs = discover_system_paths();
    let mut sources = Vec::new();
    for d in dirs {
        match source::dir(&d) {
            Ok(src) => sources.push(src),
            Err(e) => debug!(
                target: "mib_rs::searchpath",
                component = "searchpath",
                path = %d,
                reason = "open_source_failed",
                error = %e,
                "skipping system path",
            ),
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

fn discover_netsnmp_paths() -> Vec<String> {
    let mut paths = netsnmp_defaults();
    let home = HOME_DIR.as_deref();
    for cf in netsnmp_config_files() {
        paths = apply_config_file(&cf, paths, |line| {
            parse_netsnmp_line(line).map(|(op, dirs)| (op, expand_netsnmp_home(dirs, home)))
        });
    }
    if let Ok(v) = std::env::var("MIBDIRS")
        && !v.is_empty()
    {
        paths = apply_netsnmp_env(&v, paths, home);
    }
    paths
}

fn discover_libsmi_paths() -> Vec<String> {
    let mut paths = libsmi_defaults();
    for cf in libsmi_config_files() {
        paths = apply_config_file(&cf, paths, parse_libsmi_line);
    }
    if let Ok(v) = std::env::var("SMIPATH")
        && !v.is_empty()
    {
        paths = apply_libsmi_env(&v, paths);
    }
    paths
}

static HOME_DIR: LazyLock<Option<PathBuf>> = LazyLock::new(dirs::home_dir);

fn netsnmp_defaults() -> Vec<String> {
    let mut paths = Vec::new();
    if let Some(home) = HOME_DIR.as_ref() {
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
    if let Some(home) = HOME_DIR.as_ref() {
        files.push(home.join(".snmp").join("snmp.conf"));
    }
    files
}

fn libsmi_config_files() -> Vec<PathBuf> {
    let mut files = vec![PathBuf::from("/etc/smi.conf")];
    if let Some(home) = HOME_DIR.as_ref() {
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

fn apply_netsnmp_env(value: &str, current: Vec<String>, home: Option<&Path>) -> Vec<String> {
    let (op, dirs) = if let Some(rest) = value.strip_prefix('+') {
        (PathOp::Append, split_paths(rest))
    } else if let Some(rest) = value.strip_prefix('-') {
        (PathOp::Prepend, split_paths(rest))
    } else {
        (PathOp::Replace, split_paths(value))
    };
    apply_op(op, expand_netsnmp_home(dirs, home), current)
}

/// Replace every literal `$HOME` occurrence as net-snmp does.
///
/// This intentionally does not perform shell, tilde, or general environment
/// variable expansion.
fn expand_netsnmp_home(paths: Vec<String>, home: Option<&Path>) -> Vec<String> {
    let Some(home) = home else {
        return paths;
    };
    let home = home.to_string_lossy();
    paths
        .into_iter()
        .map(|path| path.replace("$HOME", home.as_ref()))
        .collect()
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

fn apply_config_file<F>(path: &Path, mut current: Vec<String>, mut parse_line: F) -> Vec<String>
where
    F: FnMut(&str) -> Option<(PathOp, Vec<String>)>,
{
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return current,
    };

    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                debug!(
                    target: "mib_rs::searchpath",
                    component = "searchpath",
                    path = %path.display(),
                    reason = "config_read_error",
                    error = %e,
                    "error reading config file",
                );
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
    fn netsnmp_home_expansion_is_literal_only() {
        let result = expand_netsnmp_home(
            vec![
                "$HOME/mibs/$HOME".into(),
                "~/mibs".into(),
                "$USER/mibs".into(),
                "${HOME}/mibs".into(),
            ],
            Some(Path::new("/home/test")),
        );
        assert_eq!(
            result,
            vec![
                "/home/test/mibs//home/test",
                "~/mibs",
                "$USER/mibs",
                "${HOME}/mibs",
            ]
        );
    }

    #[test]
    fn netsnmp_env_expands_home_before_dedup_and_filter() {
        let temp =
            std::env::temp_dir().join(format!("mib-rs-searchpath-env-{}", std::process::id()));
        let mibs = temp.join("mibs");
        std::fs::create_dir_all(&mibs).unwrap();

        let value = format!(
            "$HOME/mibs{}{}{}$HOME/missing",
            if cfg!(windows) { ';' } else { ':' },
            mibs.display(),
            if cfg!(windows) { ';' } else { ':' },
        );
        let paths = apply_netsnmp_env(&value, Vec::new(), Some(&temp));
        let paths = filter_existing_dirs(dedup(paths));

        assert_eq!(paths, vec![mibs.to_string_lossy()]);
        std::fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn netsnmp_config_expands_home_before_dedup_and_filter() {
        let temp =
            std::env::temp_dir().join(format!("mib-rs-searchpath-config-{}", std::process::id()));
        let mibs = temp.join("mibs");
        let extra = temp.join("extra");
        std::fs::create_dir_all(&mibs).unwrap();
        std::fs::create_dir_all(&extra).unwrap();
        let config = temp.join("snmp.conf");
        let separator = if cfg!(windows) { ';' } else { ':' };
        std::fs::write(
            &config,
            format!(
                "mibdirs $HOME/mibs{separator}{}\n+mibdirs $HOME/extra{separator}$HOME/missing\n",
                mibs.display()
            ),
        )
        .unwrap();

        let paths = apply_config_file(&config, Vec::new(), |line| {
            parse_netsnmp_line(line).map(|(op, dirs)| (op, expand_netsnmp_home(dirs, Some(&temp))))
        });
        let paths = filter_existing_dirs(dedup(paths));

        assert_eq!(paths, vec![mibs.to_string_lossy(), extra.to_string_lossy()]);
        std::fs::remove_dir_all(temp).unwrap();
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
