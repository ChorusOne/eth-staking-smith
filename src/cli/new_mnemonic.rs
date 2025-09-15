use crate::{key_material::KdfVariant, networks::SupportedNetworks, Validators};
use clap::{arg, Parser};

#[derive(Parser, Clone)]
pub struct NewMnemonicSubcommandOpts {
    /// The name of Ethereum PoS chain you are targeting.
    ///
    /// Use "mainnet" if you are
    /// depositing ETH
    #[arg(value_enum, long)]
    pub chain: Option<SupportedNetworks>,

    /// The number of new validator keys you want to
    /// generate.
    ///
    /// You can always generate more later
    #[arg(long, visible_alias = "num_validators")]
    pub num_validators: u32,

    /// The password that will secure your keystores.
    ///
    /// You will need to re-enter this to
    /// decrypt them when you setup your Ethereum
    /// validators. If omitted, keystores will not be generated.
    #[arg(long, visible_alias = "keystore_password")]
    pub keystore_password: Option<String>,

    /// The index of the first validator's keys you wish to generate the address for
    // e.g. if you generated 3 keys before (index #0, index #1, index #2)
    // and you want to generate for the 2nd validator,
    // the validator_start_index would be 1.
    // If no index specified, it will be set to 0.
    #[arg(long, visible_alias = "validator_start_index")]
    pub validator_start_index: Option<u32>,

    /// If this field is set and valid, the given
    /// value will be used to set the withdrawal credentials.
    /// When --compounding is specified, execution addresses and 0x01
    /// credentials will be converted to 0x02 compounding credentials.
    /// Valid formats are ^(0x[a-fA-F0-9]{40})$ for execution addresses,
    /// ^(0x01[0]{22}[a-fA-F0-9]{40})$ for execution withdrawal credentials,
    /// ^(0x02[a-fA-F0-9]{62})$ for EIP-7251 compounding withdrawal credentials (supports variable deposits up to 2048 ETH),
    /// and ^(0x00[a-fA-F0-9]{62})$ for BLS withdrawal credentials.
    #[arg(long, visible_alias = "withdrawal_credentials")]
    pub withdrawal_credentials: Option<String>,

    /// Use this argument to select the key derivation function for the keystores.
    ///
    /// Depending on your use case with `scrypt` using higher security parameters
    /// and consequently slower performance vs `pbkdf2`,
    /// achieving better performance with lower security parameters compared to `scrypt`
    #[arg(long)]
    pub kdf: Option<KdfVariant>,

    /// Path to a custom Eth PoS chain config
    #[arg(long, visible_alias = "testnet_config")]
    pub testnet_config: Option<String>,

    /// A version of CLI to include into generated deposit data
    #[arg(long, visible_alias = "deposit_cli_version", default_value = "2.7.0")]
    pub deposit_cli_version: String,

    /// Deposit amount in ETH.
    /// For standard validators: exactly 32 ETH.
    /// For EIP-7251 compounding validators (0x02 withdrawal credentials): 32 to 2048 ETH.
    /// Cannot be used together with --deposit-amount-gwei flag.
    #[arg(
        long,
        visible_alias = "deposit_amount",
        default_value = "32",
        conflicts_with = "deposit_amount_gwei"
    )]
    pub deposit_amount_eth: u64,

    /// Deposit amount in Gwei.
    /// For standard validators: exactly 32000000000 Gwei (32 ETH).
    /// For EIP-7251 compounding validators (0x02 withdrawal credentials): 32000000000 to 2048000000000 Gwei.
    /// Cannot be used together with --deposit-amount-eth flag.
    #[arg(long, conflicts_with = "deposit_amount_eth")]
    pub deposit_amount_gwei: Option<u64>,

    /// Use EIP-7251 compounding withdrawal credentials (0x02).
    ///
    /// When enabled, validators will use 0x02 withdrawal credentials which support
    /// compounding rewards and variable deposit amounts up to 2048 ETH.
    /// When disabled, validators use traditional 0x00 BLS withdrawal credentials.
    #[arg(long)]
    pub compounding: bool,
}

impl NewMnemonicSubcommandOpts {
    pub fn run(&self) {
        let chain = if self.chain.is_some() && self.testnet_config.is_some() {
            panic!("should only pass one of testnet_config or chain")
        } else if self.testnet_config.is_some() {
            // Signalizes custom testnet config will be used
            None
        } else {
            self.chain.clone()
        };

        let password = self
            .keystore_password
            .clone()
            .map(|p| p.as_bytes().to_owned());

        let deposit_amount_gwei = if let Some(gwei) = self.deposit_amount_gwei {
            gwei
        } else {
            self.deposit_amount_eth * 1_000_000_000 // Convert ETH to Gwei
        };

        let validators = Validators::new(
            None,
            password,
            Some(self.num_validators),
            None,
            self.withdrawal_credentials.is_none() || self.compounding,
            self.kdf.clone(),
        );
        let export: serde_json::Value = validators
            .export(
                chain,
                self.withdrawal_credentials.clone(),
                deposit_amount_gwei,
                self.compounding,
                self.deposit_cli_version.clone(),
                self.testnet_config.clone(),
            )
            .unwrap()
            .try_into()
            .expect("could not serialise validator export");
        let export_json =
            serde_json::to_string_pretty(&export).expect("could not parse validator export");
        println!("{}", export_json);
    }
}
