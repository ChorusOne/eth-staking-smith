use crate::utils::wallet_password_bytes;
use bip39::{Language, Mnemonic, MnemonicType};
use eth2_wallet::{Error, Wallet};

#[allow(dead_code)]
pub(crate) fn get_eth2_wallet(existing_mnemonic: Option<&[u8]>) -> Result<(Wallet, String), Error> {
    let mnemonic = match existing_mnemonic {
        Some(found_mnemonic) => {
            let phrase = std::str::from_utf8(found_mnemonic).unwrap().to_string();
            Mnemonic::from_phrase(phrase.as_str(), Language::English)
                .expect("Invalid phrase passed")
        }
        None => Mnemonic::new(MnemonicType::Words24, Language::English),
    };

    let pass = wallet_password_bytes();
    let wallet_name = uuid::Uuid::new_v4().to_string();
    let seed_phrase = mnemonic.clone().into_phrase();
    let wb = eth2_wallet::WalletBuilder::from_mnemonic(&mnemonic, &pass, wallet_name)?;
    let wallet = match wb.build() {
        Ok(w) => w,
        Err(e) => {
            return Err(e);
        }
    };
    Ok((wallet, seed_phrase))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";
    // Since it is impossible to recover phrase from wallet,
    // use internal seed as an etalon here.
    const PHRASE_SEED: &str = "5017c7d08b4b15b05e7f03df3c36b3597eb38ac1bb68b0a33f93262b035e555417288484c982e9c3d1831be2ec5acf6d49230bd3f25d22bf8dd35677c12da7c3";

    fn get_seed_from_wallet(wallet: Wallet) -> String {
        let pass = wallet_password_bytes();
        let wallet_seed = wallet.decrypt_seed(&pass).unwrap();
        hex::encode(wallet_seed)
    }

    #[test]
    fn it_creates_wallet_with_new_mnemonic() {
        let (wallet, _) = get_eth2_wallet(None).unwrap();
        assert_ne!(PHRASE_SEED, get_seed_from_wallet(wallet));
    }

    #[test]
    fn it_creates_wallet_with_existing_mnemonic() {
        let (wallet, _) = get_eth2_wallet(Some(PHRASE.as_bytes())).unwrap();
        assert_eq!(PHRASE_SEED, get_seed_from_wallet(wallet));
    }
}
