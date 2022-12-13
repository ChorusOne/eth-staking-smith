use crate::Validators;
use clap::{App, Arg, ArgMatches};

#[allow(clippy::needless_lifetimes)]
pub fn subcommand<'a, 'b>() -> App<'a, 'b> {
    App::new("existing-mnemonic")
        .about("Generate (or recover) keys from an existing mnemonic.")
        .arg(
            Arg::with_name("mnemonic")
                .long("mnemonic")
                .required(true)
                .takes_value(true)
                .help(
                    "The mnemonic that you used to generate your
                keys. (It is recommended not to use this
                argument, and wait for the CLI to ask you
                for your mnemonic as otherwise it will
                appear in your shell history.)",
                ),
        )
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
                    "The password that will secure your
                keystores. You will need to re-enter this to
                decrypt them when you setup your Ethereum
                validators. If omitted, keystores will not be generated.",
                ),
        )
        .arg(
            Arg::with_name("validator_start_index")
                .long("validator_start_index")
                .required(false)
                .takes_value(true)
                .help(
                    "The index of the first validator's keys you wish to generate e.g. if you generated 3 keys before (index #0, index #1, index #2) 
                    and you want to regenerate starting from the 2nd validator, the validator_start_index would be 1. 
                    If no start index specified, it will be set to 0.",
                ),
        )
        .arg(
            Arg::with_name("withdrawal_credentials")
                .long("withdrawal_credentials")
                .required(false)
                .takes_value(true)
                .help(
                    "If this field is set and valid, the given
                value will be used to set the
                withdrawal credentials. Otherwise, it will
                generate withdrawal credentials with the
                mnemonic-derived withdrawal public key. Valid formats are 
                ^(0x[a-fA-F0-9]{40})$ for execution addresses, 
                ^(0x01[0]{22}[a-fA-F0-9]{40})$ for execution withdrawal credentials 
                and ^(0x00[a-fA-F0-9]{62})$ for BLS withdrawal credentials.",
                ),
        )
}

#[allow(clippy::needless_lifetimes)]
pub fn run<'a>(sub_match: &ArgMatches<'a>) {
    let mnemonic = sub_match.value_of("mnemonic").unwrap();

    let num_validators = sub_match
        .value_of("num_validators")
        .expect("missing number of validators")
        .parse::<u32>()
        .expect("invalid number of validators");

    let chain = sub_match
        .value_of("chain")
        .expect("missing chain identifier");

    let keystore_password = sub_match.value_of("keystore_password");

    let validator_start_index = sub_match
        .value_of("validator_start_index")
        .map(|idx| idx.parse::<u32>().expect("invalid validator start index"));

    let withdrawal_credentials = sub_match.value_of("withdrawal_credentials");

    let validators = Validators::new(
        Some(mnemonic.as_bytes()),
        keystore_password.map(|p| p.as_bytes()),
        Some(num_validators),
        validator_start_index,
        withdrawal_credentials.is_none(),
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
