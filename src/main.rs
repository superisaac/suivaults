use clap::Parser;
use sui_types::exit_main;
use colored::Colorize;

pub mod ks_wallet;
pub mod ks_commands;
pub mod api;

#[tokio::main]
async fn main() {
    let cmd = ks_commands::KsCommand::parse();
    exit_main!(cmd.execute().await)
}
