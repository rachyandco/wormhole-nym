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
    /// Gateway identity key (base58) to connect through. Chosen randomly if omitted.
    #[arg(long, global = true)]
    gateway: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a file. Prints a wormhole code to share with the receiver.
    Send {
        /// File to send
        file: PathBuf,

        /// Limit send rate to N KiB/s. Prevents gateway queue buildup and makes
        /// the progress bar reflect actual delivery speed. Without this the SDK
        /// buffer can hold tens of thousands of packets, causing the progress bar
        /// to show ~500 KiB/s while the receiver only sees ~50 KiB/s.
        #[arg(long, default_value_t = 48)]
        rate: u32,
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
        Commands::Send { file, rate } => send::send_file(file, cli.gateway, rate).await,
        Commands::Receive { code, output } => receive::receive_file(code, output, cli.gateway).await,
    }
}
