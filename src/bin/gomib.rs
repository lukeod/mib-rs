use std::process;

use clap::Parser;

use gomib::load::{LoadOptions, load};
use gomib::mib::Mib;
use gomib::source::dir_source;
use gomib::types::{DiagnosticConfig, Kind, ReportingLevel, ResolverStrictness};

#[derive(Parser)]
#[command(name = "gomib", about = "SNMP MIB parser and resolver")]
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
        /// Module names to load (omit to load all)
        modules: Vec<String>,
        /// Use strict resolver mode
        #[arg(long)]
        strict: bool,
        /// Use permissive resolver mode
        #[arg(long)]
        permissive: bool,
        /// Reporting level (silent, quiet, default, verbose)
        #[arg(long, default_value = "default")]
        report: String,
        /// Show detailed stats
        #[arg(long)]
        stats: bool,
    },
    /// Look up an OID or name
    Get {
        /// OID or name to look up
        query: String,
        /// Module names to load
        #[arg(short = 'm', long = "module")]
        modules: Vec<String>,
        /// Load all modules from sources
        #[arg(long)]
        all: bool,
        /// Show subtree
        #[arg(short = 't', long = "tree")]
        tree: bool,
        /// Max tree depth
        #[arg(long, default_value = "0")]
        max_depth: usize,
        /// Show full descriptions (no truncation)
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
    /// Search for objects matching a pattern
    Find {
        /// Glob pattern to match
        pattern: String,
        /// Module names to load
        #[arg(short = 'm', long = "module")]
        modules: Vec<String>,
        /// Load all modules
        #[arg(long)]
        all: bool,
        /// Filter by kind (scalar, table, row, column, notification)
        #[arg(long)]
        kind: Option<String>,
        /// Print only count
        #[arg(long)]
        count: bool,
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
        } => cmd_load(&cli.paths, modules, strict, permissive, &report, stats),
        Command::Get {
            query,
            modules,
            all,
            tree,
            max_depth,
            full,
        } => cmd_get(&cli.paths, &query, modules, all, tree, max_depth, full),
        Command::List { count } => cmd_list(&cli.paths, count),
        Command::Paths => cmd_paths(&cli.paths),
        Command::Lint { modules } => cmd_lint(&cli.paths, modules),
        Command::Find {
            pattern,
            modules,
            all,
            kind,
            count,
        } => cmd_find(&cli.paths, &pattern, modules, all, kind, count),
    };

    process::exit(exit_code);
}

fn build_sources(paths: &[String]) -> Vec<Box<dyn gomib::source::Source>> {
    let mut sources = Vec::new();
    for p in paths {
        match dir_source(p) {
            Ok(src) => sources.push(src),
            Err(e) => eprintln!("warning: skipping path {p}: {e}"),
        }
    }
    sources
}

fn load_mib(
    paths: &[String],
    modules: Vec<String>,
    all: bool,
    strictness: ResolverStrictness,
    diag_config: DiagnosticConfig,
) -> Result<Mib, i32> {
    let sources = build_sources(paths);
    let use_system = sources.is_empty();

    let mut opts = LoadOptions::new()
        .sources(sources)
        .resolver_strictness(strictness)
        .diagnostic_config(diag_config);

    if use_system {
        opts = opts.system_paths();
    }

    if !all && !modules.is_empty() {
        opts = opts.modules(modules);
    }

    match load(opts) {
        Ok(r) => {
            for w in &r.warnings {
                eprintln!("warning: {w}");
            }
            Ok(r.mib)
        }
        Err(e) => {
            eprintln!("error: {e}");
            Err(1)
        }
    }
}

fn parse_reporting_level(s: &str) -> ReportingLevel {
    match s {
        "silent" => ReportingLevel::Silent,
        "quiet" => ReportingLevel::Quiet,
        "verbose" => ReportingLevel::Verbose,
        _ => ReportingLevel::Default,
    }
}

fn cmd_load(
    paths: &[String],
    modules: Vec<String>,
    strict: bool,
    permissive: bool,
    report: &str,
    stats: bool,
) -> i32 {
    let strictness = if strict {
        ResolverStrictness::Strict
    } else if permissive {
        ResolverStrictness::Permissive
    } else {
        ResolverStrictness::Normal
    };
    let diag_config = DiagnosticConfig::for_reporting(parse_reporting_level(report));

    let all = modules.is_empty();
    let mib = match load_mib(paths, modules, all, strictness, diag_config) {
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
    all: bool,
    tree: bool,
    max_depth: usize,
    full: bool,
) -> i32 {
    let load_all = all || modules.is_empty();
    let mib = match load_mib(
        paths,
        modules,
        load_all,
        ResolverStrictness::Permissive,
        DiagnosticConfig::silent(),
    ) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let node_id = match mib.resolve(query) {
        Some(id) => id,
        None => {
            eprintln!("not found: {query}");
            return 1;
        }
    };

    if tree {
        let depth = if max_depth == 0 {
            usize::MAX
        } else {
            max_depth
        };
        print_tree(&mib, node_id, 0, depth);
    } else {
        print_node_detail(&mib, node_id, full);
    }

    0
}

fn print_node_detail(mib: &Mib, node_id: gomib::mib::NodeId, full: bool) {
    let node = mib.tree().get(node_id);
    let oid = mib.tree().oid_of(node_id);

    println!("Name:    {}", node.name());
    println!("OID:     {oid}");
    println!("Kind:    {}", node.kind());

    if let Some(mod_id) = mib.effective_module(node_id) {
        println!("Module:  {}", mib.module(mod_id).name());
    }

    if let Some(obj_id) = node.object() {
        let obj = mib.object(obj_id);
        if let Some(tid) = obj.type_id() {
            let t = mib.type_(tid);
            println!(
                "Type:    {} ({})",
                t.name(),
                t.effective_base(mib.types_slice())
            );
        }
        println!("Access:  {}", obj.access());
        println!("Status:  {}", obj.status());
        if !obj.units().is_empty() {
            println!("Units:   {}", obj.units());
        }
        if let Some(dv) = obj.default_value() {
            println!("DefVal:  {dv}");
        }
        if !obj.index().is_empty() {
            let names: Vec<&str> = obj.index().iter().map(|i| i.type_name.as_str()).collect();
            println!("Index:   {}", names.join(", "));
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

        let desc = obj.description();
        if !desc.is_empty() {
            if full {
                println!("Descr:   {desc}");
            } else {
                let truncated = truncate(desc, 80);
                println!("Descr:   {truncated}");
            }
        }
    } else if let Some(notif_id) = node.notification() {
        let notif = mib.notification(notif_id);
        println!("Status:  {}", notif.status());
        let desc = notif.description();
        if !desc.is_empty() {
            if full {
                println!("Descr:   {desc}");
            } else {
                println!("Descr:   {}", truncate(desc, 80));
            }
        }
    } else {
        let desc = node.description();
        if !desc.is_empty() {
            if full {
                println!("Descr:   {desc}");
            } else {
                println!("Descr:   {}", truncate(desc, 80));
            }
        }
    }
}

fn print_tree(mib: &Mib, node_id: gomib::mib::NodeId, depth: usize, max_depth: usize) {
    if depth > max_depth {
        return;
    }
    let node = mib.tree().get(node_id);
    let indent = "  ".repeat(depth);
    let oid = mib.tree().oid_of(node_id);
    let name = if node.name().is_empty() {
        format!("[{}]", node.arc())
    } else {
        node.name().to_string()
    };

    let kind = node.kind();
    let kind_str = if kind == Kind::Internal {
        String::new()
    } else {
        format!(" ({kind})")
    };

    println!("{indent}{name} {oid}{kind_str}");

    for (&_arc, &child_id) in node.children() {
        print_tree(mib, child_id, depth + 1, max_depth);
    }
}

fn cmd_list(paths: &[String], count: bool) -> i32 {
    let sources = build_sources(paths);
    let use_system = sources.is_empty();

    let all_sources = if use_system {
        let mut s = sources;
        s.extend(gomib::searchpath::discover_system_sources());
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
    if !paths.is_empty() {
        for p in paths {
            println!("{p}");
        }
    } else {
        let system = gomib::searchpath::discover_system_paths();
        if system.is_empty() {
            eprintln!("no system MIB paths found");
        } else {
            for p in system {
                println!("{p}");
            }
        }
    }
    0
}

fn cmd_lint(paths: &[String], modules: Vec<String>) -> i32 {
    let all = modules.is_empty();
    let mib = match load_mib(
        paths,
        modules,
        all,
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
        println!("{d}");
    }
    println!();
    println!("{} issue(s) found.", mib.diagnostics().len());

    if mib.has_errors() { 1 } else { 0 }
}

fn cmd_find(
    paths: &[String],
    pattern: &str,
    modules: Vec<String>,
    all: bool,
    kind_filter: Option<String>,
    count: bool,
) -> i32 {
    let load_all = all || modules.is_empty();
    let mib = match load_mib(
        paths,
        modules,
        load_all,
        ResolverStrictness::Permissive,
        DiagnosticConfig::silent(),
    ) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let kind_match: Option<Kind> = kind_filter.as_deref().and_then(parse_kind);

    let mut matches = Vec::new();

    for obj in mib.objects_slice() {
        let name = obj.name();
        if !glob_match(pattern, name) {
            continue;
        }
        if let Some(node_id) = obj.node() {
            let node = mib.tree().get(node_id);
            let k = node.kind();
            if let Some(want) = kind_match {
                if k != want {
                    continue;
                }
            }
            let oid = mib.tree().oid_of(node_id);
            let mod_name = obj
                .module()
                .map(|mid| mib.module(mid).name())
                .unwrap_or("?");
            matches.push((
                mod_name.to_string(),
                name.to_string(),
                oid.to_string(),
                k.to_string(),
            ));
        }
    }

    matches.sort();

    if count {
        println!("{}", matches.len());
    } else {
        for (mod_name, name, oid, kind_str) in &matches {
            println!("{mod_name}::{name} {oid} {kind_str}");
        }
    }

    0
}

fn parse_kind(s: &str) -> Option<Kind> {
    match s.to_lowercase().as_str() {
        "scalar" => Some(Kind::Scalar),
        "table" => Some(Kind::Table),
        "row" => Some(Kind::Row),
        "column" => Some(Kind::Column),
        _ => None,
    }
}

fn glob_match(pattern: &str, name: &str) -> bool {
    let mut pi = pattern.chars().peekable();
    let mut ni = name.chars().peekable();

    while let Some(&pc) = pi.peek() {
        match pc {
            '*' => {
                pi.next();
                if pi.peek().is_none() {
                    return true;
                }
                while ni.peek().is_some() {
                    let remaining_name: String = ni.clone().collect();
                    let remaining_pattern: String = pi.clone().collect();
                    if glob_match(&remaining_pattern, &remaining_name) {
                        return true;
                    }
                    ni.next();
                }
                return false;
            }
            '?' => {
                pi.next();
                if ni.next().is_none() {
                    return false;
                }
            }
            c => {
                pi.next();
                match ni.next() {
                    Some(nc) if nc == c => {}
                    _ => return false,
                }
            }
        }
    }

    ni.peek().is_none()
}

fn truncate(s: &str, max_len: usize) -> String {
    let first_line = s.lines().next().unwrap_or(s);
    if first_line.len() <= max_len {
        first_line.to_string()
    } else {
        format!("{}...", &first_line[..max_len])
    }
}
