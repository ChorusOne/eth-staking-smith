use clap::App;
use eth_staking_smith::cli::{existing_mnemonic, new_mnemonic};

fn main() {
    env_logger::init();
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(&*format!("Chorus one <{}>", env!("CARGO_PKG_AUTHORS")))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .subcommand(new_mnemonic::subcommand())
        .subcommand(existing_mnemonic::subcommand())
        .get_matches();

    match matches.subcommand() {
        ("new-mnemonic", Some(sub_match)) => new_mnemonic::run(sub_match),
        ("existing-mnemonic", Some(sub_match)) => existing_mnemonic::run(sub_match),
        _ => println!("{}", matches.usage()),
    }
}
