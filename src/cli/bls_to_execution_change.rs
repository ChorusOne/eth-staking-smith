use crate::bls_to_execution_change::operations::SignedBlsToExecutionChangeValidator;
use crate::chain_spec::validators_root_and_spec;
use crate::{beacon_node::BeaconNodeExportable, bls_to_execution_change};
use clap::{arg, Parser};

#[derive(Clone, Parser)]
pub struct BlsToExecutionChangeSubcommandOpts {
    /// The mnemonic that you used to generate your
    /// keys.
    ///
    /// This can be provided in two ways:
    ///
    /// 1. Through the MNEMONIC environment variable (recommended)
    ///
    /// 2. Through the --mnemonic argument in plain text.
    #[arg(long, env = "MNEMONIC")]
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
    #[arg(long, visible_alias = "validator_seed_index")]
    pub validator_seed_index: u32,

    /// On-chain beacon index of the validator.
    #[arg(long, visible_alias = "validator_beacon_index")]
    pub validator_beacon_index: u32,

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

    /// Optional beacon node URL. If set, the bls-to-execution-change message
    /// will not be printed on stdout, but instead sent to beacon node
    #[arg(long, visible_alias = "beacon_node_uri")]
    pub beacon_node_uri: Option<url::Url>,
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

        let (bls_to_execution_change, keypair) =
            bls_to_execution_change::bls_execution_change_from_mnemonic(
                self.mnemonic.as_bytes(),
                self.validator_seed_index as u64,
                self.validator_beacon_index as u64,
                self.execution_address.as_str(),
            );

        let signed_bls_to_execution_change = bls_to_execution_change.sign(
            &keypair.withdrawal_keypair.unwrap().sk,
            genesis_validators_root,
            &spec,
        );

        signed_bls_to_execution_change.clone().validate(
            self.bls_withdrawal_credentials.as_str(),
            self.execution_address.as_str(),
            &spec,
            &genesis_validators_root,
        );

        if self.beacon_node_uri.is_some() {
            signed_bls_to_execution_change
                .send_beacon_payload(self.beacon_node_uri.clone().unwrap())
                .unwrap_or_else(|e| panic!("Failed sending beacon node payload: {:?}", e))
        } else {
            let export = signed_bls_to_execution_change.export();

            let signed_bls_to_execution_change_json =
                serde_json::to_string_pretty(&export).expect("could not parse validator export");
            println!("{}", signed_bls_to_execution_change_json);
        }
    }
}
