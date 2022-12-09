use clap::Parser;
use sui_types::exit_main;
use colored::Colorize;

pub mod wallets;
pub mod vault_commands;
pub mod api;

#[tokio::main]
async fn main() {
    let cmd = vault_commands::KsCommand::parse();
    exit_main!(cmd.execute().await)
}
