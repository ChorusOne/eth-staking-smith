use crate::Validators;
use clap::{App, Arg, ArgMatches};

#[allow(clippy::needless_lifetimes)]
pub fn subcommand<'a, 'b>() -> App<'a, 'b> {
    App::new("new-mnemonic")
        .about("Generate new keys with new mnemonic.")
        .arg(
            Arg::with_name("num_validators")
                .long("num_validators")
                .required(true)
                .takes_value(true)
                .help(
                    "The number of new validator keys you want to
                generate (you can always generate more
                later)",
                ),
        )
        .arg(
            Arg::with_name("chain")
                .long("chain")
                .required(true)
                .takes_value(true)
                .possible_values(&["goerli", "prater", "mainnet", "minimal", "holesky"])
                .help(
                    r#"The name of Ethereum PoS chain you are
                targeting. Use "mainnet" if you are
                depositing ETH"#,
                ),
        )
        .arg(
            Arg::with_name("keystore_password")
                .long("keystore_password")
                .required(false)
                .takes_value(true)
                .help(
                    "The password that will encrypt your
                keystores. You will need to re-enter this to
                decrypt them when you setup your Ethereum
                validators. If omitted, keystores will not be generated.",
                ),
        )
        .arg(
            Arg::with_name("withdrawal_credentials")
                .long("withdrawal_credentials")
                .required(false)
                .takes_value(true)
                .help(
                    "If this field is set and valid, the given
                value will be used to set the withdrawal credentials. 
                Otherwise, it will generate withdrawal credentials with the
                mnemonic-derived withdrawal public key. 
                Valid formats are ^(0x[a-fA-F0-9]{40})$ for execution addresses, 
                ^(0x01[0]{22}[a-fA-F0-9]{40})$ for execution withdrawal credentials
                and ^(0x00[a-fA-F0-9]{62})$ for BLS withdrawal credentials.",
                ),
        )
        .arg(
            Arg::with_name("kdf")
                .long("kdf")
                .required(false)
                .takes_value(true)
                .possible_values(&["scrypt", "pbkdf2"])
                .help(
                    "Use this argument to select the key derivation function for the keystores depending on your use case with `scrypt` using higher security parameters 
                    and consequently slower performance vs `pbkdf2` achieving better performance with lower security parameters compared to `scrypt`",
                ),
        )
}

#[allow(clippy::needless_lifetimes)]
pub fn run<'a>(sub_match: &ArgMatches<'a>) {
    let num_validators_str = sub_match
        .value_of("num_validators")
        .expect("missing number of validators");

    let num_validators = num_validators_str
        .parse::<u32>()
        .expect("invalid number of validators");

    let chain = sub_match
        .value_of("chain")
        .expect("missing chain identifier");

    let keystore_password = sub_match.value_of("keystore_password");

    let withdrawal_credentials = sub_match.value_of("withdrawal_credentials");

    let kdf = sub_match.value_of("kdf");

    let validators = Validators::new(
        None,
        keystore_password.map(|p| p.as_bytes()),
        Some(num_validators),
        None,
        withdrawal_credentials.is_none(),
        kdf,
    );
    let export: serde_json::Value = validators
        .export(
            chain.to_string(),
            withdrawal_credentials,
            32_000_000_000,
            "2.3.0".to_string(),
            None,
        )
        .unwrap()
        .try_into()
        .expect("could not serialise validator export");
    let export_json =
        serde_json::to_string_pretty(&export).expect("could not parse validator export");
    println!("{}", export_json);
}
