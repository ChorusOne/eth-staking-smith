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
    /// Generate (or recover) keys from an existing mnemonic.
    ExistingMnemonic(existing_mnemonic::ExistingMnemonicSubcommandOpts),
    /// Generate new keys with new mnemonic.
    NewMnemonic(new_mnemonic::NewMnemonicSubcommandOpts),
}

impl SubCommands {
    pub fn run(&self) {
        match self {
            Self::BlsToExecutionChange(sub) => sub.run(),
            Self::ExistingMnemonic(sub) => sub.run(),
            Self::NewMnemonic(sub) => sub.run(),
        }
    }
}

fn main() {
    env_logger::init();
    let opts = Opts::parse();
    opts.subcommand.run()
}
