use clap::{arg, Parser};

use crate::voluntary_exit::operator::SignedVoluntaryExitOperator;
use crate::{chain_spec::validators_root_and_spec, voluntary_exit};

#[derive(Clone, Parser)]
pub struct PresignedExitMessageSubcommandOpts {
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

    /// Epoch number which must be included in the presigned exit message.
    #[arg(long, visible_alias = "execution_address")]
    pub epoch: u64,

    /// Path to a custom Eth PoS chain config
    #[arg(long, visible_alias = "testnet_config")]
    pub testnet_config: Option<String>,

    /// Custom genesis validators root for the custom testnet, passed as hex string.
    /// See https://eth2book.info/capella/part3/containers/state/ for value
    /// description
    #[arg(long, visible_alias = "genesis_validators_root")]
    pub genesis_validators_root: Option<String>,
}

impl PresignedExitMessageSubcommandOpts {
    pub fn run(&self) {
        let chain = if self.chain.is_some() && self.testnet_config.is_some() {
            panic!("should only pass one of testnet_config or chain")
        } else if self.testnet_config.is_some() {
            // Signalizes custom testnet config will be used
            None
        } else {
            self.chain.clone()
        };

        let (genesis_validators_root, spec) = validators_root_and_spec(
            chain.clone(),
            if chain.is_some() {
                None
            } else {
                Some((
                    self.genesis_validators_root
                        .clone()
                        .expect("Genesis validators root parameter must be set"),
                    self.testnet_config
                        .clone()
                        .expect("Testnet config must be set"),
                ))
            },
        );

        let (voluntary_exit, key_material) = voluntary_exit::voluntary_exit_message_from_mnemonic(
            self.mnemonic.as_bytes(),
            self.validator_start_index as u64,
            self.validator_index as u64,
            self.epoch,
        );

        let signed_voluntary_exit =
            voluntary_exit.sign(&key_material.keypair.sk, genesis_validators_root, &spec);

        signed_voluntary_exit.clone().validate(
            &key_material.keypair.pk,
            &spec,
            &genesis_validators_root,
        );
        let export = signed_voluntary_exit.export();

        let presigned_exit_message_json =
            serde_json::to_string_pretty(&export).expect("could not parse validator export");
        println!("{}", presigned_exit_message_json);
    }
}
