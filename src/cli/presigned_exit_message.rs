use clap::{arg, Parser};

use crate::beacon_node::BeaconNodeExportable;
use crate::voluntary_exit::operations::SignedVoluntaryExitValidator;
use crate::{chain_spec::validators_root_and_spec, voluntary_exit};

#[derive(Clone, Parser)]
pub struct PresignedExitMessageSubcommandOpts {
    /// The mnemonic that you used to generate your
    /// keys.
    ///
    /// This can be provided in two ways:
    ///
    /// 1. Through the MNEMONIC environment variable (recommended)
    ///
    /// 2. Through the --mnemonic argument in plain text.
    #[arg(long, required_unless_present = "private_key", env = "MNEMONIC")]
    pub mnemonic: Option<String>,

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
    #[arg(
        long,
        visible_alias = "validator_seed_index",
        required_unless_present = "private_key"
    )]
    pub validator_seed_index: Option<u32>,

    /// Validator private key bytes in hex form
    #[arg(long, required_unless_present_all = ["mnemonic", "validator_seed_index"])]
    pub private_key: Option<String>,

    /// On-chain beacon index of the validator.
    #[arg(long, visible_alias = "validator_beacon_index")]
    pub validator_beacon_index: u32,

    /// Epoch number which must be included in the presigned exit message.
    #[arg(long)]
    pub epoch: u64,

    /// Path to a custom Eth PoS chain config
    #[arg(long, visible_alias = "testnet_config")]
    pub testnet_config: Option<String>,

    /// Custom genesis validators root for the custom testnet, passed as hex string.
    /// See https://eth2book.info/capella/part3/containers/state/ for value
    /// description
    #[arg(long, visible_alias = "genesis_validators_root")]
    pub genesis_validators_root: Option<String>,

    /// Optional beacon node URL. If set, the presigned-exit-message value
    /// will not be printed on stdout, but instead sent to beacon node
    #[arg(long, visible_alias = "beacon_node_uri")]
    pub beacon_node_uri: Option<url::Url>,
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

        let (voluntary_exit, key_material) = if self.private_key.is_some() {
            // Use private key path when available
            let secret_key_str = self.private_key.clone().unwrap();
            let secret_key_bytes =
                hex::decode(secret_key_str.strip_prefix("0x").unwrap_or(&secret_key_str))
                    .expect("Invalid private key hex input");
            voluntary_exit::voluntary_exit_message_from_secret_key(
                secret_key_bytes.as_slice(),
                self.validator_beacon_index as u64,
                self.epoch,
            )
        } else {
            // Use mnemonic path
            voluntary_exit::voluntary_exit_message_from_mnemonic(
                self.mnemonic.clone().unwrap().as_bytes(),
                self.validator_seed_index
                    .expect("validator_seed_index must be provided when using a mnemonic")
                    as u64,
                self.validator_beacon_index as u64,
                self.epoch,
            )
        };

        let signed_voluntary_exit =
            voluntary_exit.sign(&key_material.keypair.sk, genesis_validators_root, &spec);

        signed_voluntary_exit.clone().validate(
            &key_material.keypair.pk,
            &spec,
            &genesis_validators_root,
        );

        if self.beacon_node_uri.is_some() {
            signed_voluntary_exit
                .send_beacon_payload(self.beacon_node_uri.clone().unwrap())
                .unwrap_or_else(|e| panic!("Failed sending beacon node payload: {:?}", e))
        } else {
            let export = signed_voluntary_exit.export();
            let presigned_exit_message_json =
                serde_json::to_string_pretty(&export).expect("could not parse validator export");
            println!("{}", presigned_exit_message_json);
        }
    }
}
