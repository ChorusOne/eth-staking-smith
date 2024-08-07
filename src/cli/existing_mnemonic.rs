use crate::{key_material::KdfVariant, networks::SupportedNetworks, Validators};
use clap::{arg, Parser};

#[derive(Clone, Parser)]
pub struct ExistingMnemonicSubcommandOpts {
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
    /// value will be used to set the
    /// withdrawal credentials. Otherwise, it will
    /// generate withdrawal credentials with the
    /// mnemonic-derived withdrawal public key. Valid formats are
    /// ^(0x[a-fA-F0-9]{40})$ for execution addresses,
    /// ^(0x01[0]{22}[a-fA-F0-9]{40})$ for execution withdrawal credentials
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
}

impl ExistingMnemonicSubcommandOpts {
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

        let validators = Validators::new(
            Some(self.mnemonic.as_bytes()),
            password,
            Some(self.num_validators),
            self.validator_start_index,
            self.withdrawal_credentials.is_none(),
            self.kdf.clone(),
        );
        let export: serde_json::Value = validators
            .export(
                chain,
                self.withdrawal_credentials.clone(),
                32_000_000_000,
                "2.3.0".to_string(),
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
