#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use eth_staking_smith::cli::{bls_to_execution_change, existing_mnemonic, new_mnemonic};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Opts {
    #[command(subcommand)]
    subcommand: SubCommands,
}

#[derive(Subcommand)]
enum SubCommands {
    /// Generates a SignedBLSToExecutionChange object which can be sent
    /// to the Beacon Node to change the withdrawal address from BLS to an execution address
    BlsToExecutionChange(bls_to_execution_change::BlsToExecutionChangeSubcommandOpts),
    ExistingMnemonic(existing_mnemonic::ExistingMnemonicSubcommandOpts),
    NewMnemonic(new_mnemonic::NewMnemonicSubcommandOpts),
}

fn main() {
    env_logger::init();

    let opts = Opts::parse();
    match opts.subcommand {
        // Server
        SubCommands::BlsToExecutionChange(sub) => sub.run(),
        SubCommands::ExistingMnemonic(sub) => sub.run(),
        SubCommands::NewMnemonic(sub) => sub.run(),
    }
}
