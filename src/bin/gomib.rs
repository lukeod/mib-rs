use clap::Parser;

#[derive(Parser)]
#[command(name = "gomib", about = "SNMP MIB parser and resolver")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Load and validate MIB files
    Load {
        /// MIB module names or paths to load
        modules: Vec<String>,
    },
    /// Look up an OID or name
    Get {
        /// OID or name to look up
        query: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Load { modules }) => {
            eprintln!("load: not yet implemented (modules: {:?})", modules);
        }
        Some(Command::Get { query }) => {
            eprintln!("get: not yet implemented (query: {query})");
        }
        None => {
            eprintln!("gomib: no command specified. Use --help for usage.");
        }
    }
}
