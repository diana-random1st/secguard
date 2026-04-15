use clap::{Parser, Subcommand};

mod cmd_guard;
mod cmd_init;
pub(crate) mod cmd_model;
mod cmd_scan;
mod hook;

#[derive(Parser)]
#[command(
    name = "secguard",
    version,
    about = "3-level security toolkit for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan text or files for secrets
    Scan {
        /// Directory to scan (default: read from stdin)
        #[arg(long)]
        dir: Option<String>,
        /// Output format: text or json
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Check if a shell command is destructive
    Guard {
        /// Command to check (reads from stdin if not provided)
        command: Option<String>,
    },
    /// Claude Code hook mode (reads PreToolUse JSON from stdin)
    Hook {
        /// Hook type
        #[arg(value_enum)]
        mode: hook::HookMode,
    },
    /// Download ML models from GitHub Releases
    Model {
        /// Target directory (default: ~/.secguard/models/)
        #[arg(long)]
        dir: Option<String>,
    },
    /// Install secguard as Claude Code hooks
    Init {
        /// Install to global ~/.claude/settings.json (default: project .claude/settings.json)
        #[arg(long)]
        global: bool,
    },
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { dir, format } => cmd_scan::run(dir, &format),
        Commands::Guard { command } => cmd_guard::run(command),
        Commands::Hook { mode } => hook::run(mode),
        Commands::Model { dir } => cmd_model::run(dir),
        Commands::Init { global } => cmd_init::run(global),
    }
}
