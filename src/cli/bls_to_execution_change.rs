use crate::bls_to_execution_change;
use clap::{App, Arg, ArgMatches};

#[allow(clippy::needless_lifetimes)]
pub fn subcommand<'a, 'b>() -> App<'a, 'b> {
    App::new("bls-to-execution-change")
        .about("Generates a SignedBLSToExecutionChange object which can be sent to the Beacon Node to change the withdrawal address from BLS to an execution address.")
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
            Arg::with_name("chain")
                .long("chain")
                .required(true)
                .takes_value(true)
                .possible_values(&["goerli", "prater", "mainnet", "holesky"])
                .help(
                    r#"The name of Ethereum PoS chain you are
                targeting. Use "mainnet" if you are
                depositing ETH"#,
                ),
        )
        .arg(
            Arg::with_name("validator_start_index")
                .long("validator_start_index")
                .required(false)
                .takes_value(true)
                .help(
                    "The index of the first validator's keys you wish to generate the address for
                e.g. if you generated 3 keys before (index #0, index #1, index #2) 
                and you want to generate for the 2nd validator, 
                the validator_start_index would be 1. 
                If no index specified, it will be set to 0.",
                ),
        )
        .arg(
            Arg::with_name("validator_index")
                .long("validator_index")
                .required(true)
                .takes_value(true)
                .help(
                    "On-chain index of the validator.",
                ),
        )
        .arg(
            Arg::with_name("bls_withdrawal_credentials")
                .long("bls_withdrawal_credentials")
                .required(true)
                .takes_value(true)
                .help(
                    "BLS withdrawal credentials you used when depositing the validator.",
                ),
        )
        .arg(
            Arg::with_name("execution_address")
                .long("execution_address")
                .required(true)
                .takes_value(true)
                .help(
                    "Execution (0x01) address to which funds withdrawn should be sent to.",
                ),
        )
}

#[allow(clippy::needless_lifetimes)]
pub fn run<'a>(sub_match: &ArgMatches<'a>) {
    let mnemonic = sub_match.value_of("mnemonic").unwrap();

    let chain = sub_match
        .value_of("chain")
        .expect("missing chain identifier");

    let validator_start_index = sub_match
        .value_of("validator_start_index")
        .map(|idx| idx.parse::<u32>().expect("invalid validator index"))
        .unwrap_or(0);

    let validator_index = sub_match
        .value_of("validator_index")
        .map(|idx| idx.parse::<u32>().expect("invalid validator index"))
        .unwrap_or(0);

    let execution_address = sub_match.value_of("execution_address").unwrap();
    let bls_withdrawal_credentials = sub_match.value_of("bls_withdrawal_credentials").unwrap();

    let bls_to_execution_change = bls_to_execution_change::BLSToExecutionRequest::new(
        mnemonic.as_bytes(),
        validator_start_index,
        validator_index,
        execution_address,
    );

    let signed_bls_to_execution_change = bls_to_execution_change.sign(chain);

    signed_bls_to_execution_change.clone().validate(
        bls_withdrawal_credentials,
        execution_address,
        chain,
    );

    let export = signed_bls_to_execution_change.export();

    let signed_bls_to_execution_change_json =
        serde_json::to_string_pretty(&export).expect("could not parse validator export");
    println!("{}", signed_bls_to_execution_change_json);
}
