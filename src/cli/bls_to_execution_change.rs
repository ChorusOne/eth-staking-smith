use crate::bls_to_execution_change;
use clap::{arg, Parser};

#[derive(Clone, Parser)]
pub struct BlsToExecutionChangeSubcommandOpts {
    /// The mnemonic that you used to generate your
    /// keys.
    ///
    /// It is recommended not to use this
    /// argument, and wait for the CLI to ask you
    ///    for your mnemonic as otherwise it will
    ///    appear in your shell history.
    #[arg(long)]
    pub mnemonic: String,

    /// The name of Ethereum PoS chain you are targeting.
    ///
    /// Use "mainnet" if you are
    /// depositing ETH
    #[arg(value_enum, long)]
    pub chain: crate::networks::SupportedNetworks,

    /// The index of the first validator's keys you wish to generate the address for
    /// e.g. if you generated 3 keys before (index #0, index #1, index #2)
    /// and you want to generate for the 2nd validator,
    /// the validator_start_index would be 1.
    /// If no index specified, it will be set to 0.
    #[arg(long, visible_alias = "validator_start_index")]
    pub validator_start_index: u32,

    /// On-chain beacon index of the validator.
    #[arg(long, visible_alias = "validator_index")]
    pub validator_index: u32,

    /// BLS withdrawal credentials you used when depositing the validator.
    #[arg(long, visible_alias = "bls_withdrawal_credentials")]
    pub bls_withdrawal_credentials: String,

    /// Execution (0x01) address to which funds withdrawn should be sent to.
    #[arg(long, visible_alias = "execution_address")]
    pub execution_address: String,
}

impl BlsToExecutionChangeSubcommandOpts {
    pub fn run(&self) {
        let bls_to_execution_change = bls_to_execution_change::BLSToExecutionRequest::new(
            self.mnemonic.as_bytes(),
            self.validator_start_index,
            self.validator_index,
            self.execution_address.as_str(),
        );

        let signed_bls_to_execution_change = bls_to_execution_change.sign(self.chain.clone());

        signed_bls_to_execution_change.clone().validate(
            self.bls_withdrawal_credentials.as_str(),
            self.execution_address.as_str(),
            self.chain.clone(),
        );

        let export = signed_bls_to_execution_change.export();

        let signed_bls_to_execution_change_json =
            serde_json::to_string_pretty(&export).expect("could not parse validator export");
        println!("{}", signed_bls_to_execution_change_json);
    }
}
