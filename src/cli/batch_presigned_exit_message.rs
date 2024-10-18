use std::collections::HashMap;

use clap::{arg, Parser};

use crate::beacon_node::BeaconNodeExportable;
use crate::voluntary_exit::operations::SignedVoluntaryExitValidator;
use crate::{chain_spec::validators_root_and_spec, voluntary_exit};

#[derive(Clone, Parser)]
pub struct BatchPresignedExitMessageSubcommandOpts {
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

    /// This is comma separated mapping of validator seed index to
    /// validator beacon chain index. For example, to generate exit messages
    /// for a validators with seed indices 0 and 1, and beacon chain indices
    /// 111356 and 111358, pass "0:111356,1:111358" to this command.
    #[arg(long, visible_alias = "seed_beacon_mapping")]
    pub seed_beacon_mapping: String,

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
}

impl BatchPresignedExitMessageSubcommandOpts {
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

        let mut seed_beacon_mapping: HashMap<u32, u32> = HashMap::new();

        for seed_beacon_pair in self.seed_beacon_mapping.split(",") {
            let seed_beacon_pair_split = seed_beacon_pair.split(":");
            let seed_beacon_pair_vec: Vec<u32> = seed_beacon_pair_split.map(|s| s.parse().unwrap_or_else(|e| {
                panic!("Invalid seed to beacon mapping part, not parse-able as integer: {s}: {e:?}");
            })).collect();
            if seed_beacon_pair_vec.len() != 2 {
                panic!("Every mapping in seed beacon pair split must have only one seed index and beacon index")
            }
            seed_beacon_mapping.insert(
                *seed_beacon_pair_vec.first().unwrap(),
                *seed_beacon_pair_vec.get(1).unwrap(),
            );
        }

        let (voluntary_exits, key_materials) =
            voluntary_exit::voluntary_exit_message_batch_from_mnemonic(
                self.mnemonic.as_bytes(),
                seed_beacon_mapping,
                self.epoch,
            );

        let mut signed_voluntary_exits = vec![];

        for (idx, voluntary_exit) in voluntary_exits.into_iter().enumerate() {
            let key_material = key_materials.get(idx).unwrap();
            let signed_voluntary_exit =
                voluntary_exit.sign(&key_material.keypair.sk, genesis_validators_root, &spec);
            signed_voluntary_exit.clone().validate(
                &key_material.keypair.pk,
                &spec,
                &genesis_validators_root,
            );
            signed_voluntary_exits.push(signed_voluntary_exit.export());
        }
        let presigned_exit_message_batch_json =
            serde_json::to_string_pretty(&signed_voluntary_exits)
                .expect("could not parse validator export");
        println!("{}", presigned_exit_message_batch_json);
    }
}
