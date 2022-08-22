use clap::{App, Arg, ArgMatches};
use eth_staking_smith::Validators;

fn main() {
    env_logger::init();
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(&*format!("Chorus one <{}>", env!("CARGO_PKG_AUTHORS")))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(existing_mnemonic_subcommand())
        .get_matches();

    match matches.subcommand() {
        ("existing-mnemonic", Some(sub_match)) => existing_mnemonic(sub_match),
        _ => println!("{}", matches.usage()),
    }
}

#[allow(clippy::needless_lifetimes)]
pub fn existing_mnemonic_subcommand<'a, 'b>() -> App<'a, 'b> {
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
                .required(true)
                .takes_value(true)
                .help(
                    "The password that will secure your
                keystores. You will need to re-enter this to
                decrypt them when you setup your Ethereum
                validators. (It is recommended not to use
                this argument, and wait for the CLI to ask
                you for your mnemonic as otherwise it will
                appear in your shell history.)",
                ),
        )
        .arg(
            Arg::with_name("withdrawal_address")
                .long("withdrawal_address")
                .required(true)
                .takes_value(true)
                .help(
                    "If this field is set and valid, the given
                Eth1 address will be used to create the
                withdrawal credentials. Otherwise, it will
                generate withdrawal credentials with the
                mnemonic-derived withdrawal public key.",
                ),
        )
}

#[allow(clippy::needless_lifetimes)]
fn existing_mnemonic<'a>(sub_match: &ArgMatches<'a>) {
    let mnemonic = sub_match.value_of("mnemonic").unwrap();

    let num_validators_str = sub_match
        .value_of("num_validators")
        .expect("missing number of validators");

    let num_validators = num_validators_str
        .parse::<u32>()
        .expect("invalid number of validators");

    let chain = sub_match
        .value_of("chain")
        .expect("missing chain identifier");

    let keystore_password = sub_match
        .value_of("keystore_password")
        .expect("missing keystore password");

    let withdrawal_address = sub_match
        .value_of("withdrawal_address")
        .expect("missing withdrawal address");

    let mut validators = Validators::new(Some(mnemonic.as_bytes()), keystore_password.as_bytes());
    validators.init_validators(num_validators);
    let export = validators
        .export(
            chain.to_string(),
            withdrawal_address.to_string(),
            32_000_000_000,
            "2.3.0".to_string(),
            None,
        )
        .unwrap();
    println!("{}", export);
}
