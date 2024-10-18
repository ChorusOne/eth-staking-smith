#![forbid(unsafe_code)]
use clap::{Parser, Subcommand};
use eth_staking_smith::cli::{
    batch_presigned_exit_message, bls_to_execution_change, existing_mnemonic, new_mnemonic,
    presigned_exit_message,
};

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
    /// Generate presigned exit message which can be sent
    /// to the Beacon Node to start voluntary exit process for the validator
    PresignedExitMessage(presigned_exit_message::PresignedExitMessageSubcommandOpts),
    /// Generate multiple persigned exit messages from the same mnemonic
    BatchPresignedExitMessage(
        batch_presigned_exit_message::BatchPresignedExitMessageSubcommandOpts,
    ),
}

impl SubCommands {
    pub fn run(&self) {
        match self {
            Self::BlsToExecutionChange(sub) => sub.run(),
            Self::ExistingMnemonic(sub) => sub.run(),
            Self::NewMnemonic(sub) => sub.run(),
            Self::PresignedExitMessage(sub) => sub.run(),
            Self::BatchPresignedExitMessage(sub) => sub.run(),
        }
    }
}

fn main() {
    env_logger::init();
    let opts = Opts::parse();
    opts.subcommand.run()
}
