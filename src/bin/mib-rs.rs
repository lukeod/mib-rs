use std::collections::HashMap;
use std::process;

use clap::Parser;

use mib_rs::load::{Loader, load};
use mib_rs::mib::Mib;
use mib_rs::source::dir;
use mib_rs::types::{
    DiagnosticConfig, Kind, ReportingLevel, ResolverStrictness, Severity, Span,
    all_diagnostic_codes,
};

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
        /// Show full descriptions (default: whitespace-normalized, max 200 chars)
        #[arg(long)]
        full: bool,
        /// Use strict resolver mode
        #[arg(long, conflicts_with = "permissive")]
        strict: bool,
        /// Use permissive resolver mode (default for get)
        #[arg(long, conflicts_with = "strict")]
        permissive: bool,
        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// List available module names from sources
    List {
        /// Print only count
        #[arg(long)]
        count: bool,
        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// Show MIB search paths
    Paths,
    /// Load with strict diagnostics and report issues
    Lint {
        /// Module names to lint (omit to lint all)
        modules: Vec<String>,
        /// Report diagnostics up to this severity level (0=fatal..6=info, default: 3)
        #[arg(long, default_value = "3")]
        level: u8,
        /// Exit 1 if any diagnostic at this severity or below (0=fatal..6=info, default: 2)
        #[arg(long, default_value = "2")]
        fail_on: u8,
        /// Ignore diagnostic codes matching pattern (glob, repeatable)
        #[arg(long)]
        ignore: Vec<String>,
        /// Only report these diagnostic codes (glob, repeatable)
        #[arg(long)]
        only: Vec<String>,
        /// Output format
        #[arg(long, default_value = "text")]
        format: LintFormat,
        /// Group diagnostics by key
        #[arg(long)]
        group_by: Option<GroupBy>,
        /// Show summary only (counts by severity)
        #[arg(long)]
        summary: bool,
        /// No output, exit code only
        #[arg(long)]
        quiet: bool,
        /// List all diagnostic codes and exit
        #[arg(long)]
        list_codes: bool,
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
        /// Filter by base type name (case-insensitive)
        #[arg(long = "type")]
        base_type: Option<String>,
        /// Print only count
        #[arg(long)]
        count: bool,
        /// Use strict resolver mode
        #[arg(long, conflicts_with = "permissive")]
        strict: bool,
        /// Use permissive resolver mode (default for find)
        #[arg(long, conflicts_with = "strict")]
        permissive: bool,
        /// Output format
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
    /// Deep-dive inspection of a MIB symbol
    Inspect {
        /// OID, name, qualified name, or type name to inspect
        query: String,
        /// Only load specific modules (repeatable, default: all)
        #[arg(short = 'm', long = "module")]
        modules: Vec<String>,
        /// Use strict resolver mode
        #[arg(long, conflicts_with = "permissive")]
        strict: bool,
        /// Use permissive resolver mode (default for inspect)
        #[arg(long, conflicts_with = "strict")]
        permissive: bool,
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
        /// Filter to OID subtree
        #[arg(short = 'o', long)]
        oid: Option<String>,
        /// Compact JSON output (no indentation)
        #[arg(long)]
        compact: bool,
        /// Strip description fields from output
        #[arg(long)]
        no_descriptions: bool,
    },
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum LintFormat {
    Text,
    Json,
    Sarif,
    Compact,
}

#[derive(clap::ValueEnum, Clone, Copy)]
enum GroupBy {
    Module,
    Code,
    Severity,
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
            strict,
            permissive,
            format,
        } => cmd_get(
            &cli.paths, &query, modules, tree, max_depth, full, strict, permissive, format,
        ),
        Command::List { count, format } => cmd_list(&cli.paths, count, format),
        Command::Paths => cmd_paths(&cli.paths),
        Command::Lint {
            modules,
            level,
            fail_on,
            ignore,
            only,
            format,
            group_by,
            summary,
            quiet,
            list_codes,
        } => cmd_lint(
            &cli.paths, modules, level, fail_on, ignore, only, format, group_by, summary, quiet,
            list_codes,
        ),
        Command::Find {
            pattern,
            modules,
            kind,
            base_type,
            count,
            strict,
            permissive,
            format,
        } => cmd_find(
            &cli.paths, &pattern, modules, kind, base_type, count, strict, permissive, format,
        ),
        Command::Inspect {
            query,
            modules,
            strict,
            permissive,
        } => cmd_inspect(&cli.paths, &query, modules, strict, permissive),
        Command::Dump {
            modules,
            strict,
            permissive,
            report,
            oid,
            compact,
            no_descriptions,
        } => cmd_dump(
            &cli.paths,
            modules,
            strict,
            permissive,
            report,
            oid,
            compact,
            no_descriptions,
        ),
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
            Err(2)
        }
    }
}

fn resolve_strictness(
    strict: bool,
    permissive: bool,
    default: ResolverStrictness,
) -> ResolverStrictness {
    if strict {
        ResolverStrictness::Strict
    } else if permissive {
        ResolverStrictness::Permissive
    } else {
        default
    }
}

// --- load ---

fn cmd_load(
    paths: &[String],
    modules: Vec<String>,
    strict: bool,
    permissive: bool,
    report: CliReportingLevel,
    stats: bool,
) -> i32 {
    let strictness = resolve_strictness(strict, permissive, ResolverStrictness::Normal);
    let diag_config = DiagnosticConfig::for_reporting(report.into());

    let mib = match load_mib(paths, modules, strictness, diag_config) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let mod_count = mib.user_modules().count();
    let obj_count = mib.objects().count();
    let type_count = mib.types().count();
    let notif_count = mib.notifications().count();

    println!(
        "Loaded {mod_count} modules ({type_count} types, {obj_count} objects, {notif_count} notifications)"
    );

    if stats {
        println!();
        println!("Statistics:");
        println!("  Modules:        {mod_count}");
        println!("  Types:          {type_count}");
        println!("  Objects:        {obj_count}");
        println!("  Notifications:  {notif_count}");
        println!("  OID nodes:      {}", mib.node_count());
        println!("  Diagnostics:    {}", mib.diagnostics().len());

        println!();
        println!("Nodes by kind:");
        let kind_counts = count_node_kinds(&mib);
        let kinds = [
            Kind::Internal,
            Kind::Node,
            Kind::ModuleIdentity,
            Kind::ObjectIdentity,
            Kind::Scalar,
            Kind::Table,
            Kind::Row,
            Kind::Column,
            Kind::Notification,
            Kind::Group,
            Kind::Compliance,
            Kind::Capability,
        ];
        for kind in kinds {
            if let Some(&count) = kind_counts.get(&kind)
                && count > 0
            {
                println!("  {:<15} {count}", format!("{kind}:"));
            }
        }
    }

    // Diagnostics
    let diags = mib.diagnostics();
    if !diags.is_empty() {
        eprintln!();
        eprintln!("Diagnostics:");
        for d in diags {
            eprintln!("  {d}");
        }
    }

    // Unresolved references
    let unresolved = mib.unresolved();
    if !unresolved.is_empty() {
        let mut import_count = 0;
        let mut type_count = 0;
        let mut object_count = 0;
        for u in unresolved {
            match u.kind {
                mib_rs::mib::types::UnresolvedKind::Import => import_count += 1,
                mib_rs::mib::types::UnresolvedKind::Type => type_count += 1,
                mib_rs::mib::types::UnresolvedKind::Oid
                | mib_rs::mib::types::UnresolvedKind::Index
                | mib_rs::mib::types::UnresolvedKind::NotificationObject => object_count += 1,
            }
        }
        eprintln!();
        eprintln!("Unresolved references:");
        if import_count > 0 {
            eprintln!("  {import_count} imports");
        }
        if type_count > 0 {
            eprintln!("  {type_count} types");
        }
        if object_count > 0 {
            eprintln!("  {object_count} objects");
        }
    }

    let has_violations = diags.iter().any(|d| d.severity <= Severity::Error);
    if mib.has_errors() {
        2
    } else if has_violations {
        1
    } else {
        0
    }
}

fn count_node_kinds(mib: &Mib) -> HashMap<Kind, usize> {
    let mut counts = HashMap::new();
    for node in mib.root_node().subtree() {
        *counts.entry(node.kind()).or_insert(0) += 1;
    }
    counts
}

// --- get ---

#[allow(clippy::too_many_arguments)]
fn cmd_get(
    paths: &[String],
    query: &str,
    modules: Vec<String>,
    tree: bool,
    max_depth: Option<usize>,
    full: bool,
    strict: bool,
    permissive: bool,
    format: OutputFormat,
) -> i32 {
    let strictness = resolve_strictness(strict, permissive, ResolverStrictness::Permissive);
    let diag_config = if strictness == ResolverStrictness::Permissive && !strict {
        DiagnosticConfig::silent()
    } else {
        DiagnosticConfig::for_reporting(ReportingLevel::Default)
    };

    let mib = match load_mib(paths, modules, strictness, diag_config) {
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

    let show_tree = tree || max_depth.is_some();

    match format {
        OutputFormat::Text => {
            if show_tree {
                let depth = max_depth.unwrap_or(usize::MAX);
                print_tree(node, 0, depth);
            } else {
                print_node_detail(node, full);
            }
        }
        OutputFormat::Json => {
            if show_tree {
                let depth = max_depth.unwrap_or(usize::MAX);
                let json = tree_node_json(node, 0, depth);
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            } else {
                let json = node_detail_json(node, full);
                println!("{}", serde_json::to_string_pretty(&json).unwrap());
            }
        }
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
            let ranges = format_ranges(obj.effective_ranges());
            let sizes = format_ranges(obj.effective_sizes());
            let constraint = if !ranges.is_empty() {
                format!(" ({})", ranges)
            } else if !sizes.is_empty() {
                format!(" (SIZE({}))", sizes)
            } else {
                String::new()
            };
            println!(
                "Type:    {} ({}){}",
                ty.name(),
                ty.effective_base(),
                constraint
            );
        }
        println!("Access:  {}", obj.access());
        println!("Status:  {}", obj.status());

        // Index / EffectiveIndex
        let indexes: Vec<String> = obj
            .effective_indexes()
            .map(|i| {
                let mut s = i.name().to_string();
                if i.implied() {
                    s = format!("IMPLIED {s}");
                }
                let enc = i.encoding();
                if enc != mib_rs::types::IndexEncoding::Unknown {
                    s = format!("{s} [{enc}]");
                }
                s
            })
            .collect();

        // Augments / AugmentedBy
        if let Some(aug) = obj.augments() {
            println!("Augments: {}", aug.name());
        }
        if !indexes.is_empty() {
            let label = if obj.augments().is_some() {
                "EffectiveIndex"
            } else {
                "Index"
            };
            println!("{label}: [{}]", indexes.join(", "));
        }
        let aug_by: Vec<&str> = obj.augmented_by().map(|o| o.name()).collect();
        if !aug_by.is_empty() {
            println!("AugmentedBy: {}", aug_by.join(", "));
        }

        // Table structure
        if let Some(tbl) = obj.table()
            && tbl.name() != obj.name()
        {
            println!("Table:   {}", tbl.name());
        }
        if let Some(row) = obj.row()
            && row.name() != obj.name()
        {
            println!("Row:     {}", row.name());
        }
        let cols: Vec<_> = obj.columns().collect();
        if !cols.is_empty() {
            println!("Columns:");
            println!(
                "  {:<28} {:<20} {:<18} {:<18} ROLE",
                "COLUMN", "TYPE", "BASE", "ACCESS"
            );
            println!(
                "  {:<28} {:<20} {:<18} {:<18} ----",
                "------", "----", "----", "------"
            );
            for col in &cols {
                let type_name = col.ty().map(|t| t.name().to_string()).unwrap_or_default();
                let base_type = col
                    .ty()
                    .map(|t| t.effective_base().to_string())
                    .unwrap_or_default();
                let access = col.access().to_string();
                let role = if col.is_index() { "index" } else { "data" };
                println!(
                    "  {:<28} {:<20} {:<18} {:<18} {}",
                    col.name(),
                    type_name,
                    base_type,
                    access,
                    role
                );
            }
        }

        if !obj.units().is_empty() {
            println!("Units:   {}", obj.units());
        }
        if let Some(dv) = obj.default_value() {
            println!("DefVal:  {dv}");
        }
        if obj.is_column() {
            println!("IsIndex: {}", obj.is_index());
        }

        let enums = obj.effective_enums();
        if !enums.is_empty() {
            let vals: Vec<String> = enums
                .iter()
                .map(|e| format!("{}({})", e.label, e.value))
                .collect();
            println!("Values:  {}", vals.join(", "));
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
        print_reference(obj.reference());
    } else if let Some(notif) = node.notification() {
        println!("Status:  {}", notif.status());
        let objects: Vec<&str> = notif.objects().map(|o| o.name()).collect();
        if !objects.is_empty() {
            println!("Objects:");
            for name in &objects {
                println!("  {name}");
            }
        }
        print_description(notif.description(), full);
        print_reference(notif.reference());
    } else {
        print_description(node.description(), full);
        print_reference(node.reference());
    }
}

fn format_ranges(ranges: &[mib_rs::mib::types::Range]) -> String {
    if ranges.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = ranges
        .iter()
        .map(|r| {
            if r.min == r.max {
                format!("{}", r.min)
            } else {
                format!("{}..{}", r.min, r.max)
            }
        })
        .collect();
    parts.join("|")
}

fn print_description(desc: &str, full: bool) {
    if desc.is_empty() {
        return;
    }
    if full {
        println!("Descr:   {}", normalize_whitespace(desc));
    } else {
        println!("Descr:   {}", normalize_and_truncate(desc, 200));
    }
}

fn print_reference(reference: &str) {
    if !reference.is_empty() {
        println!("Ref:     {}", normalize_whitespace(reference));
    }
}

fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_and_truncate(s: &str, max_len: usize) -> String {
    let normalized = normalize_whitespace(s);
    if normalized.len() <= max_len {
        normalized
    } else {
        let end = normalized
            .char_indices()
            .map(|(i, _)| i)
            .take_while(|&i| i <= max_len)
            .last()
            .unwrap_or(0);
        format!("{}...", &normalized[..end])
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

    // Enrich tree output with type and access
    let mut extra = String::new();
    if let Some(obj) = node.object()
        && let Some(ty) = obj.ty()
    {
        extra = format!(" {} {}", ty.effective_base(), obj.access());
    }

    println!("{indent}{name} {}{kind_str}{extra}", node.oid());

    for child in node.children() {
        print_tree(child, depth + 1, max_depth);
    }
}

// JSON output for get

#[derive(serde::Serialize)]
struct NodeJson {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    oid: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    object: Option<ObjectJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification: Option<NotificationJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    type_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    base_type: Option<String>,
    access: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    units: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_value: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    indexes: Vec<IndexJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    effective_indexes: Vec<IndexJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    augments: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    augmented_by: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    table: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    row: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    columns: Vec<String>,
    is_index: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    enums: Vec<NamedValueJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    bits: Vec<NamedValueJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
}

#[derive(serde::Serialize)]
struct IndexJson {
    name: String,
    implied: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<String>,
}

#[derive(serde::Serialize)]
struct NamedValueJson {
    label: String,
    value: i64,
}

#[derive(serde::Serialize)]
struct NotificationJson {
    status: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    objects: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
}

#[derive(serde::Serialize)]
struct TreeNodeJson {
    name: String,
    arc: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<String>,
    oid: String,
    kind: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    children: Vec<TreeNodeJson>,
}

fn node_detail_json(node: mib_rs::mib::Node<'_>, full: bool) -> NodeJson {
    let module = node.module().map(|m| m.name().to_string());

    let (object, notification, desc, reference) = if let Some(obj) = node.object() {
        let obj_name = obj.name();
        let type_name = obj.ty().map(|t| t.name().to_string());
        let base_type = obj.ty().map(|t| t.effective_base().to_string());
        let idx_entries: Vec<IndexJson> = obj
            .effective_indexes()
            .map(|i| {
                let enc = i.encoding();
                IndexJson {
                    name: i.name().to_string(),
                    implied: i.implied(),
                    encoding: if enc != mib_rs::types::IndexEncoding::Unknown {
                        Some(enc.to_string())
                    } else {
                        None
                    },
                }
            })
            .collect();
        let has_augments = obj.augments().is_some();
        let (indexes, effective_indexes) = if has_augments {
            (Vec::new(), idx_entries)
        } else {
            (idx_entries, Vec::new())
        };
        let desc = format_desc(obj.description(), full);
        let reference = non_empty(obj.reference());
        let obj_json = ObjectJson {
            type_name,
            base_type,
            access: obj.access().to_string(),
            status: obj.status().to_string(),
            units: non_empty(obj.units()),
            default_value: obj.default_value().map(|dv| dv.to_string()),
            indexes,
            effective_indexes,
            augments: obj.augments().map(|a| a.name().to_string()),
            augmented_by: obj.augmented_by().map(|o| o.name().to_string()).collect(),
            table: obj
                .table()
                .filter(|t| t.name() != obj_name)
                .map(|t| t.name().to_string()),
            row: obj
                .row()
                .filter(|r| r.name() != obj_name)
                .map(|r| r.name().to_string()),
            columns: obj.columns().map(|c| c.name().to_string()).collect(),
            is_index: obj.is_index(),
            enums: obj
                .effective_enums()
                .iter()
                .map(|e| NamedValueJson {
                    label: e.label.clone(),
                    value: e.value,
                })
                .collect(),
            bits: obj
                .effective_bits()
                .iter()
                .map(|b| NamedValueJson {
                    label: b.label.clone(),
                    value: b.value,
                })
                .collect(),
            description: desc,
            reference,
        };
        (Some(obj_json), None, None, None)
    } else if let Some(notif) = node.notification() {
        let desc = format_desc(notif.description(), full);
        let reference = non_empty(notif.reference());
        let objects: Vec<String> = notif.objects().map(|o| o.name().to_string()).collect();
        let notif_json = NotificationJson {
            status: notif.status().to_string(),
            objects,
            description: desc,
            reference,
        };
        (None, Some(notif_json), None, None)
    } else {
        let desc = format_desc(node.description(), full);
        let reference = non_empty(node.reference());
        (None, None, desc, reference)
    };

    NodeJson {
        name: node.name().to_string(),
        module,
        oid: node.oid().to_string(),
        kind: node.kind().to_string(),
        object,
        notification,
        description: desc,
        reference,
    }
}

fn tree_node_json(node: mib_rs::mib::Node<'_>, depth: usize, max_depth: usize) -> TreeNodeJson {
    let children = if depth < max_depth {
        node.children()
            .map(|c| tree_node_json(c, depth + 1, max_depth))
            .collect()
    } else {
        Vec::new()
    };

    TreeNodeJson {
        name: if node.name().is_empty() {
            format!("[{}]", node.arc())
        } else {
            node.name().to_string()
        },
        arc: node.arc(),
        module: node.module().map(|m| m.name().to_string()),
        oid: node.oid().to_string(),
        kind: node.kind().to_string(),
        children,
    }
}

fn format_desc(desc: &str, full: bool) -> Option<String> {
    if desc.is_empty() {
        return None;
    }
    if full {
        Some(normalize_whitespace(desc))
    } else {
        Some(normalize_and_truncate(desc, 200))
    }
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

// --- inspect ---

fn cmd_inspect(
    paths: &[String],
    query: &str,
    modules: Vec<String>,
    strict: bool,
    permissive: bool,
) -> i32 {
    let strictness = resolve_strictness(strict, permissive, ResolverStrictness::Permissive);
    let diag_config = DiagnosticConfig::verbose();

    let mib = match load_mib(paths, modules, strictness, diag_config) {
        Ok(m) => m,
        Err(code) => return code,
    };

    // Try node resolution first.
    if let Some(node) = mib.resolve_node(query) {
        inspect_node(&mib, node);
        return 0;
    }

    // Fall back to type lookup.
    if let Some((mod_name, name)) = query.split_once("::") {
        if let Some(module) = mib.module(mod_name)
            && let Some(ty) = module.r#type(name)
        {
            inspect_standalone_type(&mib, ty);
            return 0;
        }
    } else if let Some(ty) = mib.r#type(query) {
        inspect_standalone_type(&mib, ty);
        return 0;
    }

    eprintln!("not found: {query}");
    1
}

fn inspect_node(mib: &Mib, node: mib_rs::mib::Node<'_>) {
    print_identity(node);

    if let Some(obj) = node.object() {
        inspect_object(mib, obj);
    } else if let Some(notif) = node.notification() {
        inspect_notification(mib, notif);
    } else if let Some(group) = node.group() {
        inspect_group(mib, group);
    } else if let Some(compliance) = node.compliance() {
        inspect_compliance(mib, compliance);
    } else if let Some(capability) = node.capability() {
        inspect_capability(mib, capability);
    } else {
        inspect_bare_node(mib, node);
    }
}

fn print_identity(node: mib_rs::mib::Node<'_>) {
    let label = if node.name().is_empty() {
        format!("({})", node.arc())
    } else {
        node.name().to_string()
    };
    println!("Name:    {label}");
    if let Some(module) = node.module() {
        println!("Module:  {}", module.name());
    }
    println!("OID:     {}", node.oid());
    println!("Kind:    {}", node.kind());
}

fn inspect_object(mib: &Mib, obj: mib_rs::mib::Object<'_>) {
    println!("Status:  {}", obj.status());
    println!("Access:  {}", obj.access());

    if !obj.units().is_empty() {
        println!("Units:   {}", obj.units());
    }

    if let Some(dv) = obj.default_value() {
        println!("DefVal:  {dv}");
    }

    // Type summary line.
    if let Some(ty) = obj.ty() {
        let type_name = if ty.name().is_empty() {
            ty.effective_base().to_string()
        } else {
            ty.name().to_string()
        };
        let base = ty.effective_base().to_string();
        if type_name != base {
            println!("Type:    {type_name} ({base})");
        } else {
            println!("Type:    {type_name}");
        }
    }

    // Index / augments.
    let raw_indexes: Vec<String> = obj.index().map(|i| format_index_entry(i)).collect();
    if !raw_indexes.is_empty() {
        println!("Index:   [{}]", raw_indexes.join(", "));
    }
    if let Some(aug) = obj.augments() {
        println!("Augments: {}", aug.name());
    }
    let aug_by: Vec<&str> = obj.augmented_by().map(|o| o.name()).collect();
    if !aug_by.is_empty() {
        println!("AugmentedBy: {}", aug_by.join(", "));
    }
    if obj.augments().is_some() {
        let eff_indexes: Vec<String> = obj
            .effective_indexes()
            .map(|i| format_index_entry(i))
            .collect();
        if !eff_indexes.is_empty() {
            println!("EffectiveIndex: [{}]", eff_indexes.join(", "));
        }
    }

    // Column context.
    if obj.is_column() {
        println!("IsIndex: {}", obj.is_index());
        if let Some(row) = obj.row()
            && row.name() != obj.name()
        {
            println!("Row:     {}", row.name());
        }
        if let Some(tbl) = obj.table()
            && tbl.name() != obj.name()
        {
            println!("Table:   {}", tbl.name());
        }
    }

    // Type chain.
    if let Some(ty) = obj.ty() {
        print_type_chain(ty);
    }

    // Enum/BITS.
    let enums = obj.effective_enums();
    let bits = obj.effective_bits();
    if !enums.is_empty() && bits.is_empty() {
        println!("\nValues:");
        for v in enums {
            println!("  {}({})", v.label, v.value);
        }
    }
    if !bits.is_empty() {
        println!("\nBits:");
        for b in bits {
            println!("  {}({})", b.label, b.value);
        }
    }

    // Column table for tables and rows.
    if obj.is_table() || obj.is_row() {
        let cols: Vec<_> = obj.columns().collect();
        if !cols.is_empty() {
            println!("\nColumns:");
            print_column_table(&cols);
        }
    }

    // Provenance.
    print_provenance(obj.name(), obj.module(), obj.ty());

    // Group membership.
    print_group_membership(mib, obj.node());

    // Diagnostics.
    print_scoped_diagnostics(mib, obj.module(), obj.span());
    print_related_unresolved(mib, obj.name());

    // Description / Reference.
    print_description_reference(obj.description(), obj.reference());
}

fn inspect_notification(mib: &Mib, notif: mib_rs::mib::Notification<'_>) {
    println!("Status:  {}", notif.status());

    if let Some(ti) = notif.trap_info() {
        println!("Enterprise: {}", ti.enterprise);
        println!("TrapNumber: {}", ti.trap_number);
    }

    let objects: Vec<_> = notif.objects().collect();
    if !objects.is_empty() {
        println!("\nObjects:");
        for obj in &objects {
            let mod_prefix = obj
                .module()
                .map(|m| format!("{}::", m.name()))
                .unwrap_or_default();
            println!("  {mod_prefix}{}  {}", obj.name(), obj.node().oid());
        }
    }

    // Group membership.
    if let Some(node) = notif.node() {
        print_group_membership(mib, node);
    }

    // Diagnostics.
    print_scoped_diagnostics(mib, notif.module(), notif.span());
    print_related_unresolved(mib, notif.name());

    print_description_reference(notif.description(), notif.reference());
}

fn inspect_group(mib: &Mib, g: mib_rs::mib::Group<'_>) {
    println!("Status:  {}", g.status());
    if g.is_notification_group() {
        println!("Type:    notification-group");
    } else {
        println!("Type:    object-group");
    }

    let members: Vec<_> = g.members().collect();
    if !members.is_empty() {
        println!("\nMembers:");
        for nd in &members {
            let mod_prefix = nd
                .module()
                .map(|m| format!("{}::", m.name()))
                .unwrap_or_default();
            println!("  {mod_prefix}{}  {}  {}", nd.name(), nd.oid(), nd.kind());
        }
    }

    // Which compliances reference this group.
    print_compliance_references(mib, g.name());

    // Diagnostics.
    print_scoped_diagnostics(mib, g.module(), g.span());
    print_related_unresolved(mib, g.name());

    print_description_reference(g.description(), g.reference());
}

fn inspect_compliance(mib: &Mib, c: mib_rs::mib::Compliance<'_>) {
    println!("Status:  {}", c.status());

    for cm in c.modules() {
        let mod_name = if cm.module_name.is_empty() {
            "(this module)"
        } else {
            &cm.module_name
        };
        println!("\nModule: {mod_name}");
        if !cm.mandatory_groups.is_empty() {
            println!("  Mandatory groups: {}", cm.mandatory_groups.join(", "));
        }
        for cg in &cm.groups {
            println!("  Group: {}", cg.group);
            if !cg.description.is_empty() {
                println!("    {}", normalize_and_truncate(&cg.description, 200));
            }
        }
        for co in &cm.objects {
            println!("  Object: {}", co.object);
            if let Some(access) = co.min_access {
                println!("    MIN-ACCESS: {access}");
            }
            if !co.description.is_empty() {
                println!("    {}", normalize_and_truncate(&co.description, 200));
            }
        }
    }

    // Diagnostics.
    print_scoped_diagnostics(mib, c.module(), c.span());
    print_related_unresolved(mib, c.name());

    print_description_reference(c.description(), c.reference());
}

fn inspect_capability(mib: &Mib, cap: mib_rs::mib::Capability<'_>) {
    println!("Status:  {}", cap.status());

    if !cap.product_release().is_empty() {
        println!("Product: {}", cap.product_release());
    }

    for sm in cap.supports() {
        println!("\nSupports: {}", sm.module_name);
        if !sm.includes.is_empty() {
            println!("  Includes: {}", sm.includes.join(", "));
        }
        for ov in &sm.object_variations {
            println!("  Variation: {}", ov.object);
            if let Some(access) = ov.access {
                println!("    ACCESS: {access}");
            }
            if !ov.description.is_empty() {
                println!("    {}", normalize_and_truncate(&ov.description, 200));
            }
        }
        for nv in &sm.notification_variations {
            println!("  Variation: {}", nv.notification);
            if let Some(access) = nv.access {
                println!("    ACCESS: {access}");
            }
            if !nv.description.is_empty() {
                println!("    {}", normalize_and_truncate(&nv.description, 200));
            }
        }
    }

    // Diagnostics.
    print_scoped_diagnostics(mib, cap.module(), cap.span());
    print_related_unresolved(mib, cap.name());

    print_description_reference(cap.description(), cap.reference());
}

fn inspect_bare_node(mib: &Mib, node: mib_rs::mib::Node<'_>) {
    if node.kind() == Kind::ObjectIdentity {
        if let Some(s) = node.status() {
            println!("Status:  {s}");
        }
        println!("Macro:   OBJECT-IDENTITY");
    }

    print_scoped_diagnostics(mib, node.module(), node.span());
    print_related_unresolved(mib, node.name());

    print_description_reference(node.description(), node.reference());
}

fn inspect_standalone_type(mib: &Mib, ty: mib_rs::mib::Type<'_>) {
    println!("Name:    {}", ty.name());
    if let Some(module) = ty.module() {
        println!("Module:  {}", module.name());
    }
    println!("Kind:    type");
    let status = ty.status();
    if status != mib_rs::types::Status::Current {
        println!("Status:  {status}");
    }
    if ty.is_textual_convention() {
        println!("Macro:   TEXTUAL-CONVENTION");
    }
    println!("Base:    {}", ty.effective_base());

    print_type_chain(ty);

    print_scoped_diagnostics(mib, ty.module(), ty.span());
    print_related_unresolved(mib, ty.name());

    print_description_reference(ty.description(), ty.reference());
}

fn print_type_chain(ty: mib_rs::mib::Type<'_>) {
    println!("\nType chain:");
    let mut cur = Some(ty);
    let mut depth = 0;
    while let Some(t) = cur {
        if depth >= 100 {
            break;
        }

        let name = if t.name().is_empty() {
            "(inline)"
        } else {
            t.name()
        };

        let mod_name = t.module().map(|m| m.name().to_string()).unwrap_or_default();

        // Build annotations.
        let mut tags = Vec::new();
        if t.is_textual_convention() {
            tags.push("textual-convention".to_string());
        }
        let base = t.base();
        if base != mib_rs::types::BaseType::Unknown {
            tags.push(format!("base: {base}"));
        }

        let tag_str = if tags.is_empty() {
            String::new()
        } else {
            format!("  ({})", tags.join(", "))
        };

        if !mod_name.is_empty() {
            println!("  {:<28} {mod_name}{tag_str}", name);
        } else {
            println!("  {name}{tag_str}");
        }

        // Constraints declared at this level.
        let hint = t.display_hint();
        if !hint.is_empty() {
            println!("    DISPLAY-HINT {hint:?}");
        }
        let sizes = t.sizes();
        if !sizes.is_empty() {
            println!("    SIZE ({})", format_range_list(sizes));
        }
        let ranges = t.ranges();
        if !ranges.is_empty() {
            println!("    RANGE ({})", format_range_list(ranges));
        }
        let enums = t.enums();
        if !enums.is_empty() {
            let labels: Vec<String> = enums
                .iter()
                .map(|e| format!("{}({})", e.label, e.value))
                .collect();
            println!("    VALUES: {}", labels.join(", "));
        }
        let bits = t.bits();
        if !bits.is_empty() {
            let labels: Vec<String> = bits
                .iter()
                .map(|b| format!("{}({})", b.label, b.value))
                .collect();
            println!("    BITS: {}", labels.join(", "));
        }

        cur = t.parent();
        depth += 1;
    }
}

fn format_index_entry(i: mib_rs::mib::Index<'_>) -> String {
    let mut s = i.name().to_string();
    if i.implied() {
        s = format!("IMPLIED {s}");
    }
    let enc = i.encoding();
    if enc != mib_rs::types::IndexEncoding::Unknown {
        s = format!("{s} [{enc}]");
    }
    s
}

fn format_range_list(ranges: &[mib_rs::mib::types::Range]) -> String {
    let parts: Vec<String> = ranges
        .iter()
        .map(|r| {
            if r.min == r.max {
                format!("{}", r.min)
            } else {
                format!("{}..{}", r.min, r.max)
            }
        })
        .collect();
    parts.join(" | ")
}

fn print_provenance(
    name: &str,
    module: Option<mib_rs::mib::Module<'_>>,
    ty: Option<mib_rs::mib::Type<'_>>,
) {
    println!("\nProvenance:");
    if let Some(m) = module {
        println!("  {:<24} defined in {}", name, m.name());
    }

    let ty = match ty {
        Some(t) => t,
        None => return,
    };

    let mut seen = std::collections::HashSet::new();
    let mut cur = Some(ty);
    while let Some(t) = cur {
        let t_name = t.name();
        if !t_name.is_empty() && seen.insert(t_name.to_string()) {
            let t_mod = t.module().map(|m| m.name().to_string()).unwrap_or_default();

            // Check if this type was imported by the object's module.
            let source = if let Some(ref m) = module {
                let mod_name = m.name();
                if !t_mod.is_empty() && t_mod != mod_name {
                    if m.imports_symbol(t_name) {
                        if let Some(src_mod) = m.import_source(t_name) {
                            format!(
                                "  imported from {} (via {} IMPORTS)",
                                src_mod.name(),
                                mod_name
                            )
                        } else {
                            format!("  imported from {t_mod} (via {mod_name} IMPORTS)")
                        }
                    } else {
                        format!("  defined in {t_mod}")
                    }
                } else if !t_mod.is_empty() {
                    format!("  defined in {t_mod}")
                } else {
                    String::new()
                }
            } else if !t_mod.is_empty() {
                format!("  defined in {t_mod}")
            } else {
                String::new()
            };

            let label = if t.is_textual_convention() {
                format!("TC {t_name}")
            } else {
                format!("Type {t_name}")
            };
            println!("  {label:<24}{source}");
        }
        cur = t.parent();
    }
}

fn print_group_membership(mib: &Mib, node: mib_rs::mib::Node<'_>) {
    let mut groups = Vec::new();
    for g in mib.groups() {
        let is_member = g.members().any(|m| m == node);
        if !is_member {
            continue;
        }
        let mod_name = g.module().map(|m| m.name().to_string()).unwrap_or_default();
        let kind = if g.is_notification_group() {
            "notification-group"
        } else {
            "object-group"
        };
        groups.push(format!("  {}  ({}, {})", g.name(), mod_name, kind));
    }
    if !groups.is_empty() {
        println!("\nGroup membership:");
        for g in &groups {
            println!("{g}");
        }
    }
}

fn print_compliance_references(mib: &Mib, group_name: &str) {
    let mut refs = Vec::new();
    for c in mib.compliances() {
        for cm in c.modules() {
            if cm.mandatory_groups.iter().any(|g| g == group_name) {
                let mod_name = c.module().map(|m| m.name().to_string()).unwrap_or_default();
                refs.push(format!("  {}  ({}, mandatory)", c.name(), mod_name));
            }
            for cg in &cm.groups {
                if cg.group == group_name {
                    let mod_name = c.module().map(|m| m.name().to_string()).unwrap_or_default();
                    refs.push(format!("  {}  ({}, conditional)", c.name(), mod_name));
                }
            }
        }
    }
    if !refs.is_empty() {
        println!("\nReferenced by compliances:");
        for r in &refs {
            println!("{r}");
        }
    }
}

fn print_scoped_diagnostics(mib: &Mib, module: Option<mib_rs::mib::Module<'_>>, span: Span) {
    let module = match module {
        Some(m) => m,
        None => return,
    };
    if span == Span::ZERO || span == Span::SYNTHETIC {
        return;
    }

    let (start_line, _) = module.line_col(span.start);
    let (end_line, _) = module.line_col(span.end);
    if start_line == 0 {
        return;
    }

    let module_name = module.name();
    let scoped: Vec<_> = mib
        .diagnostics()
        .iter()
        .filter(|d| {
            d.module.as_deref() == Some(module_name)
                && d.line.is_some_and(|l| l >= start_line && l <= end_line)
        })
        .collect();

    if !scoped.is_empty() {
        println!("\nDiagnostics:");
        for d in &scoped {
            println!("  [{}] {}: {}", d.severity, d.code, d.message);
        }
    }
}

fn print_related_unresolved(mib: &Mib, name: &str) {
    let related: Vec<_> = mib
        .unresolved()
        .iter()
        .filter(|u| u.symbol == name)
        .collect();

    if !related.is_empty() {
        println!("\nUnresolved references:");
        for u in &related {
            let mut entry = format!("  [{}] {} in {}", u.kind, u.symbol, u.module);
            if !u.reason.is_empty() {
                entry += ": ";
                entry += &u.reason;
            }
            println!("{entry}");
        }
    }
}

fn print_description_reference(desc: &str, reference: &str) {
    if !desc.is_empty() {
        println!("\nDescription:\n  {}", normalize_whitespace(desc));
    }
    if !reference.is_empty() {
        println!("\nReference:\n  {}", normalize_whitespace(reference));
    }
}

fn print_column_table(cols: &[mib_rs::mib::Object<'_>]) {
    println!(
        "  {:<28} {:<20} {:<18} {:<18} ROLE",
        "COLUMN", "TYPE", "BASE", "ACCESS"
    );
    println!(
        "  {:<28} {:<20} {:<18} {:<18} ----",
        "------", "----", "----", "------"
    );
    for col in cols {
        let type_name = col
            .ty()
            .map(|t| {
                let n = t.name();
                if n.is_empty() {
                    t.effective_base().to_string()
                } else {
                    n.to_string()
                }
            })
            .unwrap_or_default();
        let base_type = col
            .ty()
            .map(|t| t.effective_base().to_string())
            .unwrap_or_default();
        let access = col.access().to_string();
        let role = if col.is_index() { "index" } else { "data" };
        println!(
            "  {:<28} {:<20} {:<18} {:<18} {}",
            col.name(),
            type_name,
            base_type,
            access,
            role
        );
    }
}

// --- list ---

fn cmd_list(paths: &[String], count: bool, format: OutputFormat) -> i32 {
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
        return 0;
    }

    let mut sorted: Vec<_> = names.into_iter().collect();
    sorted.sort();

    match format {
        OutputFormat::Text => {
            for name in sorted {
                println!("{name}");
            }
        }
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&sorted).unwrap());
        }
    }

    0
}

// --- paths ---

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

// --- lint ---

struct LintDiagnostic {
    severity: String,
    severity_num: u8,
    code: String,
    message: String,
    module: String,
    line: usize,
    column: usize,
}

struct LintSummary {
    total: usize,
    by_severity: HashMap<String, usize>,
    by_code: HashMap<String, usize>,
    modules: usize,
}

struct LintResult {
    diagnostics: Vec<LintDiagnostic>,
    summary: LintSummary,
    exit_code: i32,
}

#[allow(clippy::too_many_arguments)]
fn cmd_lint(
    paths: &[String],
    modules: Vec<String>,
    level: u8,
    fail_on: u8,
    ignore: Vec<String>,
    only: Vec<String>,
    format: LintFormat,
    group_by: Option<GroupBy>,
    summary: bool,
    quiet: bool,
    list_codes: bool,
) -> i32 {
    if list_codes {
        print_diagnostic_codes();
        return 0;
    }

    // Load with verbose+fatal-only so we collect everything, filter client-side
    let mut diag_config = DiagnosticConfig::verbose();
    diag_config.fail_at = Severity::Fatal;

    let mib = match load_mib(paths, modules, ResolverStrictness::Strict, diag_config) {
        Ok(m) => m,
        Err(_) => return 2,
    };

    let mod_count = mib.user_modules().count();
    let diags = mib.diagnostics();

    // Filter diagnostics
    let level_sev = severity_from_num(level);
    let fail_sev = severity_from_num(fail_on);

    let mut result = LintResult {
        diagnostics: Vec::new(),
        summary: LintSummary {
            total: 0,
            by_severity: HashMap::new(),
            by_code: HashMap::new(),
            modules: mod_count,
        },
        exit_code: 0,
    };

    for d in diags {
        // Filter by level
        if let Some(max_sev) = level_sev
            && d.severity > max_sev
        {
            continue;
        }

        let code_str = d.code.as_code();

        // Filter by ignore
        if ignore.iter().any(|pat| glob_match(pat, code_str)) {
            continue;
        }

        // Filter by only
        if !only.is_empty() && !only.iter().any(|pat| glob_match(pat, code_str)) {
            continue;
        }

        let sev_str = d.severity.to_string();
        *result
            .summary
            .by_severity
            .entry(sev_str.clone())
            .or_insert(0) += 1;
        *result
            .summary
            .by_code
            .entry(code_str.to_string())
            .or_insert(0) += 1;
        result.summary.total += 1;

        // Check fail threshold
        if let Some(fail_threshold) = fail_sev
            && d.severity <= fail_threshold
        {
            result.exit_code = 1;
        }

        result.diagnostics.push(LintDiagnostic {
            severity: sev_str,
            severity_num: d.severity as u8,
            code: code_str.to_string(),
            message: d.message.clone(),
            module: d.module.clone().unwrap_or_default(),
            line: d.line.unwrap_or(0),
            column: d.column.unwrap_or(0),
        });
    }

    if quiet {
        return result.exit_code;
    }

    match format {
        LintFormat::Text => print_lint_text(&result, group_by, summary),
        LintFormat::Json => print_lint_json(&result),
        LintFormat::Sarif => print_lint_sarif(&result),
        LintFormat::Compact => print_lint_compact(&result, summary),
    }

    result.exit_code
}

fn severity_from_num(n: u8) -> Option<Severity> {
    match n {
        0 => Some(Severity::Fatal),
        1 => Some(Severity::Severe),
        2 => Some(Severity::Error),
        3 => Some(Severity::Minor),
        4 => Some(Severity::Style),
        5 => Some(Severity::Warning),
        6 => Some(Severity::Info),
        _ => None,
    }
}

const SEVERITY_ORDER: &[&str] = &[
    "fatal", "severe", "error", "minor", "style", "warning", "info",
];

fn print_lint_text(result: &LintResult, group_by: Option<GroupBy>, summary_only: bool) {
    if summary_only {
        print_lint_summary(result);
        return;
    }

    if result.diagnostics.is_empty() {
        println!("No issues found.");
        return;
    }

    match group_by {
        None => {
            for d in &result.diagnostics {
                let loc = format_lint_location(d);
                println!("{}: [{}] {}: {}", d.severity, d.code, loc, d.message);
            }
        }
        Some(GroupBy::Module) => {
            let mut by_module: HashMap<&str, Vec<&LintDiagnostic>> = HashMap::new();
            for d in &result.diagnostics {
                by_module
                    .entry(if d.module.is_empty() {
                        "<unknown>"
                    } else {
                        &d.module
                    })
                    .or_default()
                    .push(d);
            }
            let mut modules: Vec<_> = by_module.keys().copied().collect();
            modules.sort();
            for module in modules {
                println!("{module}:");
                for d in &by_module[module] {
                    let loc = format_lint_location(d);
                    println!("  {}: [{}] {}: {}", d.severity, d.code, loc, d.message);
                }
            }
        }
        Some(GroupBy::Code) => {
            let mut by_code: HashMap<&str, Vec<&LintDiagnostic>> = HashMap::new();
            for d in &result.diagnostics {
                by_code.entry(&d.code).or_default().push(d);
            }
            let mut codes: Vec<_> = by_code.keys().copied().collect();
            codes.sort();
            for code in codes {
                let items = &by_code[code];
                println!("{code} ({}):", items.len());
                for d in items {
                    let loc = format_lint_location(d);
                    println!("  {}: {}", loc, d.message);
                }
            }
        }
        Some(GroupBy::Severity) => {
            let mut by_sev: HashMap<&str, Vec<&LintDiagnostic>> = HashMap::new();
            for d in &result.diagnostics {
                by_sev.entry(&d.severity).or_default().push(d);
            }
            for sev in SEVERITY_ORDER {
                if let Some(items) = by_sev.get(sev) {
                    println!("{sev} ({}):", items.len());
                    for d in items {
                        let loc = format_lint_location(d);
                        println!("  [{}] {}: {}", d.code, loc, d.message);
                    }
                }
            }
        }
    }

    println!();
    print_lint_summary(result);
}

fn format_lint_location(d: &LintDiagnostic) -> String {
    if d.module.is_empty() {
        return String::new();
    }
    if d.line > 0 {
        if d.column > 0 {
            format!("{}:{}:{}", d.module, d.line, d.column)
        } else {
            format!("{}:{}", d.module, d.line)
        }
    } else {
        d.module.clone()
    }
}

fn print_lint_summary(result: &LintResult) {
    println!(
        "Checked {} modules, found {} issues:",
        result.summary.modules, result.summary.total
    );
    for sev in SEVERITY_ORDER {
        if let Some(&count) = result.summary.by_severity.get(*sev)
            && count > 0
        {
            println!("  {:<8} {count}", format!("{sev}:"));
        }
    }
}

fn print_lint_compact(result: &LintResult, summary_only: bool) {
    if summary_only {
        let mut parts = Vec::new();
        if let Some(&c) = result.summary.by_severity.get("error")
            && c > 0
        {
            parts.push(format!("{c} errors"));
        }
        if let Some(&c) = result.summary.by_severity.get("minor")
            && c > 0
        {
            parts.push(format!("{c} minor"));
        }
        if let Some(&c) = result.summary.by_severity.get("style")
            && c > 0
        {
            parts.push(format!("{c} style"));
        }
        print!("{} issues", result.summary.total);
        if !parts.is_empty() {
            print!(" ({})", parts.join(", "));
        }
        println!();
        return;
    }

    for d in &result.diagnostics {
        let loc = if d.module.is_empty() {
            String::new()
        } else if d.line > 0 && d.column > 0 {
            format!("{}:{}:{}", d.module, d.line, d.column)
        } else if d.line > 0 {
            format!("{}:{}", d.module, d.line)
        } else {
            d.module.clone()
        };
        println!("{loc}: {} [{}] {}", d.severity, d.code, d.message);
    }
}

fn print_lint_json(result: &LintResult) {
    #[derive(serde::Serialize)]
    struct JsonResult {
        diagnostics: Vec<JsonDiag>,
        summary: JsonSummary,
    }

    #[derive(serde::Serialize)]
    struct JsonDiag {
        severity: String,
        severity_num: u8,
        code: String,
        message: String,
        #[serde(skip_serializing_if = "String::is_empty")]
        module: String,
        #[serde(skip_serializing_if = "is_zero")]
        line: usize,
        #[serde(skip_serializing_if = "is_zero")]
        column: usize,
        rule_id: String,
    }

    #[derive(serde::Serialize)]
    struct JsonSummary {
        total: usize,
        by_severity: HashMap<String, usize>,
        by_code: HashMap<String, usize>,
        modules: usize,
    }

    let json = JsonResult {
        diagnostics: result
            .diagnostics
            .iter()
            .map(|d| JsonDiag {
                severity: d.severity.clone(),
                severity_num: d.severity_num,
                code: d.code.clone(),
                message: d.message.clone(),
                module: d.module.clone(),
                line: d.line,
                column: d.column,
                rule_id: d.code.clone(),
            })
            .collect(),
        summary: JsonSummary {
            total: result.summary.total,
            by_severity: result.summary.by_severity.clone(),
            by_code: result.summary.by_code.clone(),
            modules: result.summary.modules,
        },
    };

    println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

fn is_zero(v: &usize) -> bool {
    *v == 0
}

fn print_lint_sarif(result: &LintResult) {
    #[derive(serde::Serialize)]
    struct SarifLog {
        #[serde(rename = "$schema")]
        schema: String,
        version: String,
        runs: Vec<SarifRun>,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifRun {
        tool: SarifTool,
        results: Vec<SarifResult>,
    }

    #[derive(serde::Serialize)]
    struct SarifTool {
        driver: SarifDriver,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifDriver {
        name: String,
        information_uri: String,
        rules: Vec<SarifRule>,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifRule {
        id: String,
        short_description: SarifMessage,
        default_configuration: SarifDefaultConfig,
    }

    #[derive(serde::Serialize)]
    struct SarifDefaultConfig {
        level: String,
    }

    #[derive(serde::Serialize)]
    struct SarifMessage {
        text: String,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifResult {
        rule_id: String,
        level: String,
        message: SarifMessage,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        locations: Vec<SarifLocation>,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifLocation {
        physical_location: SarifPhysicalLocation,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation,
        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<SarifRegion>,
    }

    #[derive(serde::Serialize)]
    struct SarifArtifactLocation {
        uri: String,
    }

    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct SarifRegion {
        start_line: usize,
        #[serde(skip_serializing_if = "is_zero")]
        start_column: usize,
    }

    fn severity_to_sarif(sev: &str) -> &str {
        match sev {
            "fatal" | "severe" | "error" => "error",
            "minor" | "style" | "warning" => "warning",
            "info" => "note",
            _ => "warning",
        }
    }

    // Collect unique rules
    let mut seen_rules = std::collections::HashSet::new();
    let mut rules = Vec::new();
    for d in &result.diagnostics {
        if seen_rules.insert(d.code.clone()) {
            rules.push(SarifRule {
                id: d.code.clone(),
                short_description: SarifMessage {
                    text: d.code.clone(),
                },
                default_configuration: SarifDefaultConfig {
                    level: severity_to_sarif(&d.severity).to_string(),
                },
            });
        }
    }

    let results: Vec<SarifResult> = result
        .diagnostics
        .iter()
        .map(|d| {
            let locations = if !d.module.is_empty() {
                vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: d.module.clone(),
                        },
                        region: if d.line > 0 {
                            Some(SarifRegion {
                                start_line: d.line,
                                start_column: d.column,
                            })
                        } else {
                            None
                        },
                    },
                }]
            } else {
                Vec::new()
            };
            SarifResult {
                rule_id: d.code.clone(),
                level: severity_to_sarif(&d.severity).to_string(),
                message: SarifMessage {
                    text: d.message.clone(),
                },
                locations,
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".to_string(),
        version: "2.1.0".to_string(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "mib-rs".to_string(),
                    information_uri: "https://github.com/lukeod/mib-rs".to_string(),
                    rules,
                },
            },
            results,
        }],
    };

    println!("{}", serde_json::to_string_pretty(&log).unwrap());
}

fn print_diagnostic_codes() {
    let mut current_phase = "";
    for &code in all_diagnostic_codes() {
        let phase = code.phase();
        if phase != current_phase {
            if !current_phase.is_empty() {
                println!();
            }
            println!("{phase}:");
            current_phase = phase;
        }
        println!("  {:<36} {}", code.as_code(), code.severity());
    }
}

// --- find ---

#[allow(clippy::too_many_arguments)]
fn cmd_find(
    paths: &[String],
    pattern: &str,
    modules: Vec<String>,
    kind_filter: Option<CliKind>,
    base_type: Option<String>,
    count: bool,
    strict: bool,
    permissive: bool,
    format: OutputFormat,
) -> i32 {
    let strictness = resolve_strictness(strict, permissive, ResolverStrictness::Permissive);
    let diag_config = if strictness == ResolverStrictness::Permissive && !strict {
        DiagnosticConfig::silent()
    } else {
        DiagnosticConfig::for_reporting(ReportingLevel::Default)
    };

    let mib = match load_mib(paths, modules, strictness, diag_config) {
        Ok(m) => m,
        Err(code) => return code,
    };

    let kind_match: Option<Kind> = kind_filter.map(Kind::from);
    let base_lower = base_type.as_ref().map(|s| s.to_lowercase());

    let mut matches = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Collect matching entities via handle iterators
    for obj in mib.objects() {
        if !glob_match(pattern, obj.name()) {
            continue;
        }
        let node = obj.node();
        let node_id = node.id();
        if !seen.insert(node_id) {
            continue;
        }
        let k = node.kind();
        if kind_match.is_some_and(|want| k != want) {
            continue;
        }
        // Type filter
        if let Some(ref base) = base_lower
            && !match_base_type_obj(&obj, base)
        {
            continue;
        }
        let mod_name = obj.module().map(|m| m.name()).unwrap_or("?");
        matches.push((
            mod_name.to_string(),
            obj.name().to_string(),
            node.oid().to_string(),
            k.to_string(),
        ));
    }

    for notif in mib.notifications() {
        if !glob_match(pattern, notif.name()) {
            continue;
        }
        if let Some(node) = notif.node() {
            let node_id = node.id();
            if !seen.insert(node_id) {
                continue;
            }
            let k = node.kind();
            if kind_match.is_some_and(|want| k != want) {
                continue;
            }
            let mod_name = notif.module().map(|m| m.name()).unwrap_or("?");
            matches.push((
                mod_name.to_string(),
                notif.name().to_string(),
                node.oid().to_string(),
                k.to_string(),
            ));
        }
    }

    for grp in mib.groups() {
        if !glob_match(pattern, grp.name()) {
            continue;
        }
        if let Some(node) = grp.node() {
            let node_id = node.id();
            if !seen.insert(node_id) {
                continue;
            }
            let k = node.kind();
            if kind_match.is_some_and(|want| k != want) {
                continue;
            }
            let mod_name = grp.module().map(|m| m.name()).unwrap_or("?");
            matches.push((
                mod_name.to_string(),
                grp.name().to_string(),
                node.oid().to_string(),
                k.to_string(),
            ));
        }
    }

    for comp in mib.compliances() {
        if !glob_match(pattern, comp.name()) {
            continue;
        }
        if let Some(node) = comp.node() {
            let node_id = node.id();
            if !seen.insert(node_id) {
                continue;
            }
            let k = node.kind();
            if kind_match.is_some_and(|want| k != want) {
                continue;
            }
            let mod_name = comp.module().map(|m| m.name()).unwrap_or("?");
            matches.push((
                mod_name.to_string(),
                comp.name().to_string(),
                node.oid().to_string(),
                k.to_string(),
            ));
        }
    }

    for cap in mib.capabilities() {
        if !glob_match(pattern, cap.name()) {
            continue;
        }
        if let Some(node) = cap.node() {
            let node_id = node.id();
            if !seen.insert(node_id) {
                continue;
            }
            let k = node.kind();
            if kind_match.is_some_and(|want| k != want) {
                continue;
            }
            let mod_name = cap.module().map(|m| m.name()).unwrap_or("?");
            matches.push((
                mod_name.to_string(),
                cap.name().to_string(),
                node.oid().to_string(),
                k.to_string(),
            ));
        }
    }

    // Walk the OID tree for nodes not covered above (module-identity, object-identity, plain nodes)
    for node in mib.root_node().subtree() {
        let name = node.name();
        if name.is_empty() || !glob_match(pattern, name) {
            continue;
        }
        let node_id = node.id();
        if !seen.insert(node_id) {
            continue;
        }
        let k = node.kind();
        if k == Kind::Internal || k == Kind::Unknown {
            continue;
        }
        if kind_match.is_some_and(|want| k != want) {
            continue;
        }
        let mod_name = node
            .module()
            .map(|m| m.name().to_string())
            .unwrap_or_else(|| "?".to_string());
        matches.push((
            mod_name,
            name.to_string(),
            node.oid().to_string(),
            k.to_string(),
        ));
    }

    matches.sort();

    if count {
        println!("{}", matches.len());
    } else {
        match format {
            OutputFormat::Text => {
                for (mod_name, name, oid, kind_str) in &matches {
                    println!("{mod_name}::{name} {oid} {kind_str}");
                }
            }
            OutputFormat::Json => {
                #[derive(serde::Serialize)]
                struct FindMatch {
                    name: String,
                    module: String,
                    oid: String,
                    kind: String,
                }
                let json_matches: Vec<FindMatch> = matches
                    .iter()
                    .map(|(module, name, oid, kind)| FindMatch {
                        name: name.clone(),
                        module: module.clone(),
                        oid: oid.clone(),
                        kind: kind.clone(),
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_matches).unwrap());
            }
        }
    }

    if matches.is_empty() { 1 } else { 0 }
}

fn match_base_type_obj(obj: &mib_rs::mib::Object<'_>, base_lower: &str) -> bool {
    match obj.ty() {
        Some(ty) => ty.effective_base().to_string().to_lowercase() == *base_lower,
        None => false,
    }
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

// --- dump ---

#[allow(clippy::too_many_arguments)]
fn cmd_dump(
    paths: &[String],
    modules: Vec<String>,
    strict: bool,
    permissive: bool,
    report: CliReportingLevel,
    oid_filter: Option<String>,
    compact: bool,
    no_descriptions: bool,
) -> i32 {
    let strictness = resolve_strictness(strict, permissive, ResolverStrictness::Normal);
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

    let mut payload = mib_rs::export::export_payload(&mib, strictness);

    // Apply --oid filter
    if let Some(ref oid_prefix) = oid_filter {
        filter_export_by_oid(&mut payload, oid_prefix);
    }

    // Apply --no-descriptions
    if no_descriptions {
        strip_descriptions(&mut payload);
    }

    let json_result = if compact {
        serde_json::to_string(&payload)
    } else {
        serde_json::to_string_pretty(&payload)
    };

    match json_result {
        Ok(json) => {
            println!("{json}");
            if mib.has_errors() { 1 } else { 0 }
        }
        Err(e) => {
            eprintln!("error: failed to serialize: {e}");
            2
        }
    }
}

fn filter_export_by_oid(payload: &mut mib_rs::export::ExportPayload, oid_prefix: &str) {
    let prefix_dot = format!("{oid_prefix}.");
    let matches_oid = |oid: &str| -> bool { oid == oid_prefix || oid.starts_with(&prefix_dot) };

    payload.nodes.retain(|n| matches_oid(&n.oid));
    payload.objects.retain(|o| matches_oid(&o.oid));
    payload.notifications.retain(|n| matches_oid(&n.oid));
    payload.groups.retain(|g| matches_oid(&g.oid));
    payload.compliances.retain(|c| matches_oid(&c.oid));
    payload.capabilities.retain(|c| matches_oid(&c.oid));
}

fn strip_descriptions(payload: &mut mib_rs::export::ExportPayload) {
    for m in &mut payload.modules {
        m.description = None;
        for r in &mut m.revisions {
            r.description = None;
        }
    }
    for t in &mut payload.types {
        t.description = None;
    }
    for n in &mut payload.nodes {
        n.description = None;
    }
    for o in &mut payload.objects {
        o.description = None;
    }
    for n in &mut payload.notifications {
        n.description = None;
    }
    for g in &mut payload.groups {
        g.description = None;
    }
    for c in &mut payload.compliances {
        c.description = None;
        for cm in &mut c.modules {
            for cg in &mut cm.groups {
                cg.description = None;
            }
            for co in &mut cm.objects {
                co.description = None;
            }
        }
    }
    for c in &mut payload.capabilities {
        c.description = None;
    }
}

// --- shared utilities ---

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
