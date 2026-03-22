mod crypto;
mod protocol;
mod receive;
mod send;
mod words;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "wormhole-nym")]
#[command(
    version,
    about = "P2P file transfer over the Nym mixnet — no relay server"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file. Prints a wormhole code to share with the receiver.
    Send {
        /// File to send
        file: PathBuf,
    },
    /// Receive a file using the wormhole code from the sender.
    Receive {
        /// Wormhole code printed by the sender (format: "word-word-word:NymAddress")
        code: String,

        /// Directory to save the received file (default: current directory)
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Suppress noisy nym-sdk internal logs (backlog warnings, duplicate fragments,
    // bandwidth notices, etc.).  Set RUST_LOG=debug to see everything.
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "error");
    }
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Send { file } => send::send_file(file).await,
        Commands::Receive { code, output } => receive::receive_file(code, output).await,
    }
}
