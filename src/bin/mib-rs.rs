use std::process;

use clap::Parser;

use mib_rs::load::{Loader, load};
use mib_rs::mib::Mib;
use mib_rs::source::dir;
use mib_rs::types::{DiagnosticConfig, Kind, ReportingLevel, ResolverStrictness};

#[derive(clap::ValueEnum, Clone, Copy)]
enum CliReportingLevel {
    Silent,
    Quiet,
    Default,
    Verbose,
}

impl From<CliReportingLevel> for ReportingLevel {
    fn from(level: CliReportingLevel) -> Self {
        match level {
            CliReportingLevel::Silent => ReportingLevel::Silent,
            CliReportingLevel::Quiet => ReportingLevel::Quiet,
            CliReportingLevel::Default => ReportingLevel::Default,
            CliReportingLevel::Verbose => ReportingLevel::Verbose,
        }
    }
}

#[derive(Parser)]
#[command(name = "mib-rs", version, about = "SNMP MIB parser and resolver")]
struct Cli {
    /// MIB search paths (repeatable). If none given, uses system paths.
    #[arg(short = 'p', long = "path", global = true)]
    paths: Vec<String>,

    /// Increase verbosity (-v = debug, -vv = trace)
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Load and validate MIB modules
    Load {
        /// Module names to load (omit to load all available modules)
        modules: Vec<String>,
        /// Use strict resolver mode
        #[arg(long, conflicts_with = "permissive")]
        strict: bool,
        /// Use permissive resolver mode
        #[arg(long, conflicts_with = "strict")]
        permissive: bool,
        /// Reporting level
        #[arg(long, default_value = "default")]
        report: CliReportingLevel,
        /// Show detailed stats
        #[arg(long)]
        stats: bool,
    },
    /// Look up an OID or name
    Get {
        /// OID or name to look up
        query: String,
        /// Only load specific modules (repeatable, default: all)
        #[arg(short = 'm', long = "module")]
        modules: Vec<String>,
        /// Show subtree
        #[arg(short = 't', long = "tree")]
        tree: bool,
        /// Max tree depth (implies --tree)
        #[arg(long)]
        max_depth: Option<usize>,
        /// Show full descriptions (default: first line, max 80 chars)
        #[arg(long)]
        full: bool,
    },
    /// List available module names from sources
    List {
        /// Print only count
        #[arg(long)]
        count: bool,
    },
    /// Show MIB search paths
    Paths,
    /// Load with strict diagnostics and report issues
    Lint {
        /// Module names to lint (omit to lint all)
        modules: Vec<String>,
    },
    /// Search for nodes matching a pattern (case-insensitive, * and ? wildcards)
    Find {
        /// Name pattern to match (case-insensitive, * and ? wildcards)
        pattern: String,
        /// Only load specific modules (repeatable, default: all)
        #[arg(short = 'm', long = "module")]
        modules: Vec<String>,
        /// Filter by kind
        #[arg(long)]
        kind: Option<CliKind>,
        /// Print only count
        #[arg(long)]
        count: bool,
    },
    /// Export resolved MIB data as JSON
    Dump {
        /// Module names to load (omit to load all available modules)
        modules: Vec<String>,
        /// Use strict resolver mode
        #[arg(long, conflicts_with = "permissive")]
        strict: bool,
        /// Use permissive resolver mode
        #[arg(long, conflicts_with = "strict")]
        permissive: bool,
        /// Reporting level
        #[arg(long, default_value = "default")]
        report: CliReportingLevel,
    },
}

fn main() {
    let cli = Cli::parse();

    // Set up tracing based on verbosity
    if cli.verbose > 0 {
        let level = match cli.verbose {
            1 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        };
        tracing_subscriber::fmt()
            .with_max_level(level)
            .with_target(false)
            .init();
    }

    let exit_code = match cli.command {
        Command::Load {
            modules,
            strict,
            permissive,
            report,
            stats,
        } => cmd_load(&cli.paths, modules, strict, permissive, report, stats),
        Command::Get {
            query,
            modules,
            tree,
            max_depth,
            full,
        } => cmd_get(&cli.paths, &query, modules, tree, max_depth, full),
        Command::List { count } => cmd_list(&cli.paths, count),
        Command::Paths => cmd_paths(&cli.paths),
        Command::Lint { modules } => cmd_lint(&cli.paths, modules),
        Command::Find {
            pattern,
            modules,
            kind,
            count,
        } => cmd_find(&cli.paths, &pattern, modules, kind, count),
        Command::Dump {
            modules,
            strict,
            permissive,
            report,
        } => cmd_dump(&cli.paths, modules, strict, permissive, report),
    };

    process::exit(exit_code);
}

fn build_sources(paths: &[String]) -> Vec<Box<dyn mib_rs::source::Source>> {
    let mut sources = Vec::new();
    for p in paths {
        match dir(p) {
            Ok(src) => sources.push(src),
            Err(e) => eprintln!("warning: skipping path {p}: {e}"),
        }
    }
    sources
}

fn load_mib(
    paths: &[String],
    modules: Vec<String>,
    strictness: ResolverStrictness,
    diag_config: DiagnosticConfig,
) -> Result<Mib, i32> {
    let sources = build_sources(paths);
    let use_system = sources.is_empty();

    let mut opts = Loader::new()
        .sources(sources)
        .resolver_strictness(strictness)
        .diagnostic_config(diag_config);

    if use_system {
        opts = opts.system_paths();
    }

    if !modules.is_empty() {
        opts = opts.modules(modules);
    }

    match load(opts) {
        Ok(mib) => Ok(mib),
        Err(e) => {
            eprintln!("error: {e}");
            Err(1)
        }
    }
}

fn cmd_load(
    paths: &[String],
    modules: Vec<String>,
    strict: bool,
    permissive: bool,
    report: CliReportingLevel,
    stats: bool,
) -> i32 {
    let strictness = if strict {
        ResolverStrictness::Strict
    } else if permissive {
        ResolverStrictness::Permissive
    } else {
        ResolverStrictness::Normal
    };
    let diag_config = DiagnosticConfig::for_reporting(report.into());

    let mib = match load_mib(paths, modules, strictness, diag_config) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let mod_count = mib.modules_slice().iter().filter(|m| !m.is_base()).count();
    let obj_count = mib.objects_slice().len();
    let type_count = mib.types_slice().len();
    let notif_count = mib.notifications_slice().len();

    println!(
        "Loaded {mod_count} modules ({type_count} types, {obj_count} objects, {notif_count} notifications)"
    );

    if stats {
        println!();
        println!("  Nodes:         {}", mib.node_count());
        println!("  Tables:        {}", mib.tables().len());
        println!("  Rows:          {}", mib.rows().len());
        println!("  Columns:       {}", mib.columns().len());
        println!("  Scalars:       {}", mib.scalars().len());
        println!("  Groups:        {}", mib.groups_slice().len());
        println!("  Compliances:   {}", mib.compliances_slice().len());
        println!("  Capabilities:  {}", mib.capabilities_slice().len());
        println!("  Diagnostics:   {}", mib.diagnostics().len());
        println!("  Unresolved:    {}", mib.unresolved().len());
    }

    // Print diagnostics
    for d in mib.diagnostics() {
        eprintln!("{d}");
    }

    if mib.has_errors() { 1 } else { 0 }
}

fn cmd_get(
    paths: &[String],
    query: &str,
    modules: Vec<String>,
    tree: bool,
    max_depth: Option<usize>,
    full: bool,
) -> i32 {
    let mib = match load_mib(
        paths,
        modules,
        ResolverStrictness::Permissive,
        DiagnosticConfig::silent(),
    ) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let node = match mib.resolve_node(query) {
        Some(n) => n,
        None => {
            eprintln!("not found: {query}");
            return 1;
        }
    };

    // --max-depth implies --tree
    let show_tree = tree || max_depth.is_some();

    if show_tree {
        let depth = match max_depth {
            None => usize::MAX,
            Some(d) => d,
        };
        print_tree(node, 0, depth);
    } else {
        print_node_detail(node, full);
    }

    0
}

fn print_node_detail(node: mib_rs::mib::Node<'_>, full: bool) {
    println!("Name:    {}", node.name());
    println!("OID:     {}", node.oid());
    println!("Kind:    {}", node.kind());

    if let Some(module) = node.module() {
        println!("Module:  {}", module.name());
    }

    if let Some(obj) = node.object() {
        if let Some(ty) = obj.ty() {
            println!("Type:    {} ({})", ty.name(), ty.effective_base());
        }
        println!("Access:  {}", obj.access());
        println!("Status:  {}", obj.status());
        if !obj.units().is_empty() {
            println!("Units:   {}", obj.units());
        }
        if let Some(dv) = obj.default_value() {
            println!("DefVal:  {dv}");
        }
        let indexes: Vec<&str> = obj.effective_indexes().map(|i| i.name()).collect();
        if !indexes.is_empty() {
            println!("Index:   {}", indexes.join(", "));
        }
        let enums = obj.effective_enums();
        if !enums.is_empty() {
            let vals: Vec<String> = enums
                .iter()
                .map(|e| format!("{}({})", e.label, e.value))
                .collect();
            println!("Enums:   {}", vals.join(", "));
        }
        let bits = obj.effective_bits();
        if !bits.is_empty() {
            let vals: Vec<String> = bits
                .iter()
                .map(|b| format!("{}({})", b.label, b.value))
                .collect();
            println!("Bits:    {}", vals.join(", "));
        }

        print_description(obj.description(), full);
    } else if let Some(notif) = node.notification() {
        println!("Status:  {}", notif.status());
        print_description(notif.description(), full);
    } else {
        print_description(node.description(), full);
    }
}

fn print_description(desc: &str, full: bool) {
    if desc.is_empty() {
        return;
    }
    if full {
        println!("Descr:   {desc}");
    } else {
        println!("Descr:   {}", truncate(desc, 80));
    }
}

fn print_tree(node: mib_rs::mib::Node<'_>, depth: usize, max_depth: usize) {
    if depth > max_depth {
        return;
    }
    let indent = "  ".repeat(depth);
    let name = if node.name().is_empty() {
        format!("[{}]", node.arc())
    } else {
        node.name().to_string()
    };

    let kind = node.kind();
    let kind_str = if kind == Kind::Internal || kind == Kind::Unknown {
        String::new()
    } else {
        format!(" ({kind})")
    };

    println!("{indent}{name} {}{kind_str}", node.oid());

    for child in node.children() {
        print_tree(child, depth + 1, max_depth);
    }
}

fn cmd_list(paths: &[String], count: bool) -> i32 {
    let sources = build_sources(paths);
    let use_system = sources.is_empty();

    let all_sources = if use_system {
        let mut s = sources;
        s.extend(mib_rs::searchpath::discover_system_sources());
        s
    } else {
        sources
    };

    if all_sources.is_empty() {
        eprintln!("no MIB sources found");
        return 1;
    }

    let mut names = std::collections::HashSet::new();
    for src in &all_sources {
        match src.list_modules() {
            Ok(modules) => {
                for name in modules {
                    names.insert(name);
                }
            }
            Err(e) => eprintln!("warning: {e}"),
        }
    }

    if count {
        println!("{}", names.len());
    } else {
        let mut sorted: Vec<_> = names.into_iter().collect();
        sorted.sort();
        for name in sorted {
            println!("{name}");
        }
    }

    0
}

fn cmd_paths(paths: &[String]) -> i32 {
    let custom: std::collections::HashSet<&str> = paths.iter().map(|s| s.as_str()).collect();
    let system = mib_rs::searchpath::discover_system_paths();

    let mut all_paths: Vec<(&str, &str)> = Vec::new();
    for p in paths {
        all_paths.push((p.as_str(), "custom"));
    }
    for p in &system {
        if !custom.contains(p.as_str()) {
            all_paths.push((p.as_str(), "system"));
        }
    }

    if all_paths.is_empty() {
        eprintln!("no MIB paths found");
        return 1;
    }

    for (p, source) in &all_paths {
        println!("{p}  ({source})");
    }
    0
}

fn cmd_lint(paths: &[String], modules: Vec<String>) -> i32 {
    let mib = match load_mib(
        paths,
        modules,
        ResolverStrictness::Strict,
        DiagnosticConfig::verbose(),
    ) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let diags = mib.diagnostics();
    if diags.is_empty() {
        println!("No issues found.");
        return 0;
    }

    for d in diags {
        eprintln!("{d}");
    }
    eprintln!();
    eprintln!("{} issue(s) found.", diags.len());

    if mib.has_errors() { 1 } else { 0 }
}

fn cmd_find(
    paths: &[String],
    pattern: &str,
    modules: Vec<String>,
    kind_filter: Option<CliKind>,
    count: bool,
) -> i32 {
    let mib = match load_mib(
        paths,
        modules,
        ResolverStrictness::Permissive,
        DiagnosticConfig::silent(),
    ) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let kind_match: Option<Kind> = kind_filter.map(Kind::from);

    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Helper closure to collect a match
    let mut add_match =
        |node_id: mib_rs::mib::NodeId, name: &str, mod_id: Option<mib_rs::mib::ModuleId>| {
            if !seen.insert(node_id) {
                return;
            }
            let node = mib.tree().get(node_id);
            let k = node.kind();
            if let Some(want) = kind_match
                && k != want
            {
                return;
            }
            let oid = mib.tree().oid_of(node_id);
            let mod_name = mod_id
                .map(|mid| mib.raw().module(mid).name())
                .unwrap_or("?");
            matches.push((
                mod_name.to_string(),
                name.to_string(),
                oid.to_string(),
                k.to_string(),
            ));
        };

    for obj in mib.objects_slice() {
        if !glob_match(pattern, obj.name()) {
            continue;
        }
        if let Some(node_id) = obj.node() {
            add_match(node_id, obj.name(), obj.module());
        }
    }

    for notif in mib.notifications_slice() {
        if !glob_match(pattern, notif.name()) {
            continue;
        }
        if let Some(node_id) = notif.node() {
            add_match(node_id, notif.name(), notif.module());
        }
    }

    for grp in mib.groups_slice() {
        if !glob_match(pattern, grp.name()) {
            continue;
        }
        if let Some(node_id) = grp.node() {
            add_match(node_id, grp.name(), grp.module());
        }
    }

    for comp in mib.compliances_slice() {
        if !glob_match(pattern, comp.name()) {
            continue;
        }
        if let Some(node_id) = comp.node() {
            add_match(node_id, comp.name(), comp.module());
        }
    }

    for cap in mib.capabilities_slice() {
        if !glob_match(pattern, cap.name()) {
            continue;
        }
        if let Some(node_id) = cap.node() {
            add_match(node_id, cap.name(), cap.module());
        }
    }

    // Walk the OID tree for nodes not covered above (module-identity, object-identity, plain nodes)
    fn walk_tree_find(
        mib: &Mib,
        node_id: mib_rs::mib::NodeId,
        pattern: &str,
        kind_match: Option<Kind>,
        seen: &mut std::collections::HashSet<mib_rs::mib::NodeId>,
        matches: &mut Vec<(String, String, String, String)>,
    ) {
        let node = mib.tree().get(node_id);
        let name = node.name();
        if !name.is_empty() && !seen.contains(&node_id) && glob_match(pattern, name) {
            let k = node.kind();
            let passes = match kind_match {
                Some(want) => k == want,
                None => true,
            };
            if passes && k != Kind::Internal && k != Kind::Unknown {
                seen.insert(node_id);
                let oid = mib.tree().oid_of(node_id);
                let mod_name = mib
                    .effective_module(node_id)
                    .map(|mid| mib.raw().module(mid).name().to_string())
                    .unwrap_or_else(|| "?".to_string());
                matches.push((mod_name, name.to_string(), oid.to_string(), k.to_string()));
            }
        }
        for (&_arc, &child_id) in node.children() {
            walk_tree_find(mib, child_id, pattern, kind_match, seen, matches);
        }
    }

    walk_tree_find(
        &mib,
        mib.tree().root(),
        pattern,
        kind_match,
        &mut seen,
        &mut matches,
    );

    matches.sort();

    if count {
        println!("{}", matches.len());
    } else {
        for (mod_name, name, oid, kind_str) in &matches {
            println!("{mod_name}::{name} {oid} {kind_str}");
        }
    }

    if matches.is_empty() { 1 } else { 0 }
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum CliKind {
    Node,
    Scalar,
    Table,
    Row,
    Column,
    Notification,
    Group,
    Compliance,
    Capability,
    #[value(name = "module-identity")]
    ModuleIdentity,
    #[value(name = "object-identity")]
    ObjectIdentity,
}

impl From<CliKind> for Kind {
    fn from(k: CliKind) -> Self {
        match k {
            CliKind::Node => Kind::Node,
            CliKind::Scalar => Kind::Scalar,
            CliKind::Table => Kind::Table,
            CliKind::Row => Kind::Row,
            CliKind::Column => Kind::Column,
            CliKind::Notification => Kind::Notification,
            CliKind::Group => Kind::Group,
            CliKind::Compliance => Kind::Compliance,
            CliKind::Capability => Kind::Capability,
            CliKind::ModuleIdentity => Kind::ModuleIdentity,
            CliKind::ObjectIdentity => Kind::ObjectIdentity,
        }
    }
}

fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().flat_map(|c| c.to_lowercase()).collect();
    let name: Vec<char> = name.chars().flat_map(|c| c.to_lowercase()).collect();
    let mut pi = 0;
    let mut ni = 0;
    let mut star_pi = None;
    let mut star_ni = 0;

    while ni < name.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == name[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star_pi = Some(pi);
            star_ni = ni;
            pi += 1;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ni += 1;
            ni = star_ni;
        } else {
            return false;
        }
    }

    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }

    pi == pattern.len()
}

fn cmd_dump(
    paths: &[String],
    modules: Vec<String>,
    strict: bool,
    permissive: bool,
    report: CliReportingLevel,
) -> i32 {
    let strictness = if strict {
        ResolverStrictness::Strict
    } else if permissive {
        ResolverStrictness::Permissive
    } else {
        ResolverStrictness::Normal
    };
    let mib = match load_mib(
        paths,
        modules,
        strictness,
        DiagnosticConfig::for_reporting(report.into()),
    ) {
        Ok(m) => m,
        Err(code) => return code,
    };

    for d in mib.diagnostics() {
        eprintln!("{d}");
    }

    let payload = mib_rs::export::export_v1(&mib, strictness);
    match serde_json::to_string_pretty(&payload) {
        Ok(json) => {
            println!("{json}");
            if mib.has_errors() { 1 } else { 0 }
        }
        Err(e) => {
            eprintln!("error: failed to serialize: {e}");
            1
        }
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    let first_line = s.lines().next().unwrap_or(s);
    if first_line.len() <= max_len {
        first_line.to_string()
    } else {
        let end = first_line
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max_len)
            .last()
            .unwrap_or(0);
        format!("{}...", &first_line[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn glob_match_matches_literals_and_wildcards() {
        assert!(glob_match("sys*", "sysDescr"));
        assert!(glob_match("if?ndex", "ifIndex"));
        assert!(glob_match("*Entry", "ifTableEntry"));
        assert!(glob_match("foo**bar", "foobazbar"));
    }

    #[test]
    fn glob_match_is_case_insensitive() {
        assert!(glob_match("SYS*", "sysDescr"));
        assert!(glob_match("sys*", "SysDescr"));
        assert!(glob_match("IF-MIB", "IF-MIB"));
        assert!(glob_match("if-mib", "IF-MIB"));
    }

    #[test]
    fn glob_match_rejects_non_matches() {
        assert!(!glob_match("if?ndex", "ifXIndex"));
        assert!(!glob_match("sys*", "ifDescr"));
        assert!(!glob_match("*Entry", "ifTable"));
    }

    #[test]
    fn glob_match_handles_empty_inputs() {
        assert!(glob_match("", ""));
        assert!(glob_match("*", ""));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("", "sysDescr"));
    }
}
