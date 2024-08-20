use crate::bls_to_execution_change::operator::SignedBlsToExecutionChangeOperator;
use crate::{bls_to_execution_change, chain_spec};
use clap::{arg, Parser};
use types::Hash256;

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
    pub chain: Option<crate::networks::SupportedNetworks>,

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

    /// Path to a custom Eth PoS chain config
    #[arg(long, visible_alias = "testnet_config")]
    pub testnet_config: Option<String>,

    /// Custom genesis validators root for the custom testnet, passed as hex string.
    /// See https://eth2book.info/capella/part3/containers/state/ for value
    /// description
    #[arg(long, visible_alias = "genesis_validators_root")]
    pub genesis_validators_root: Option<String>,
}

impl BlsToExecutionChangeSubcommandOpts {
    pub fn run(&self) {
        let chain = if self.chain.is_some() && self.testnet_config.is_some() {
            panic!("should only pass one of testnet_config or chain")
        } else if self.testnet_config.is_some() {
            // Signalizes custom testnet config will be used
            None
        } else {
            self.chain.clone()
        };

        let (genesis_validator_root, spec) = if chain.is_some() {
            let well_known_chain = chain.unwrap();
            (
                bls_to_execution_change::constants::validators_root_for(&well_known_chain),
                chain_spec::chain_spec_for_network(&well_known_chain).expect("Invalid chain spec"),
            )
        } else {
            let genesis_validators_root_str = self.genesis_validators_root.clone().expect("If custom testnet config is passed, genesis validators root value must be included");
            let genesis_validators_root_bytes = hex::decode(
                genesis_validators_root_str
                    .strip_prefix("0x")
                    .unwrap_or(&genesis_validators_root_str),
            )
            .expect("Invalid custom genesis validators root");
            (
                Hash256::from_slice(genesis_validators_root_bytes.as_slice()),
                chain_spec::chain_spec_from_file(self.testnet_config.clone().unwrap())
                    .expect("Invalid chain spec in file"),
            )
        };

        let (bls_to_execution_change, keypair) =
            bls_to_execution_change::bls_execution_change_from_mnemonic(
                self.mnemonic.as_bytes(),
                self.validator_start_index as u64,
                self.validator_index as u64,
                self.execution_address.as_str(),
            );

        let signed_bls_to_execution_change = bls_to_execution_change.sign(
            &keypair.withdrawal_keypair.unwrap().sk,
            genesis_validator_root,
            &spec,
        );

        signed_bls_to_execution_change.clone().validate(
            self.bls_withdrawal_credentials.as_str(),
            self.execution_address.as_str(),
            &spec,
            &genesis_validator_root,
        );

        let export = signed_bls_to_execution_change.export();

        let signed_bls_to_execution_change_json =
            serde_json::to_string_pretty(&export).expect("could not parse validator export");
        println!("{}", signed_bls_to_execution_change_json);
    }
}
