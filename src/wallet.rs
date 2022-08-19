use bip39::{Language, Mnemonic, MnemonicType};
use eth2_wallet::{Error, Wallet};
use rand::{distributions::Alphanumeric, Rng};

lazy_static! {
    /// Generate temporary random password of 32 bytes.
    /// This password is only used to encrypt Wallet in memory and dropped
    /// after the program concludes.
    pub static ref WALLET_PASSWORD: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(13)
        .collect();
}

#[allow(dead_code)]
fn get_eth2_wallet(existing_mnemonic: Option<&[u8]>) -> Result<Wallet, Error> {
    let seed_phrase: String = if let Some(found_mnemonic) = existing_mnemonic {
        std::str::from_utf8(found_mnemonic).unwrap().to_string()
    } else {
        let new_mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        new_mnemonic.phrase().to_string()
    };

    let wallet_name = uuid::Uuid::new_v4().to_string();
    let wb = eth2_wallet::WalletBuilder::from_seed_bytes(
        seed_phrase.as_bytes(),
        &WALLET_PASSWORD,
        wallet_name,
    )?;
    wb.build()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";

    fn get_phrase_from_wallet(wallet: Result<Wallet, Error>) -> String {
        let wallet_mnemonic = wallet.unwrap().decrypt_seed(&WALLET_PASSWORD).unwrap();
        std::str::from_utf8(wallet_mnemonic.as_bytes())
            .unwrap()
            .to_string()
    }

    #[test]
    fn it_creates_wallet_with_new_mnemonic() {
        let wallet = get_eth2_wallet(None);
        assert_eq!(false, wallet.is_err());
        assert_ne!(PHRASE, get_phrase_from_wallet(wallet));
    }

    #[test]
    fn it_creates_wallet_with_existing_mnemonic() {
        let wallet = get_eth2_wallet(Some(PHRASE.as_bytes()));
        assert_eq!(false, wallet.is_err());
        assert_eq!(PHRASE, get_phrase_from_wallet(wallet));
    }
}
