use riir_deposit_cli::keystore::WALLET_PASSWORD;

pub fn main() {
    println!("{:?}", String::from_utf8(WALLET_PASSWORD.to_vec()));
}
