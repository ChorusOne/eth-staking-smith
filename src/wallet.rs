use crate::utils::{pbkdf2, wallet_password_bytes};
use bip39::{Language, Mnemonic, MnemonicType, Seed as Bip39Seed};
use eth2_key_derivation::PlainText;
use eth2_keystore::json_keystore::{Cipher, Kdf};
use eth2_keystore::{encrypt, IV_SIZE};
use eth2_wallet::json_wallet::{
    Aes128Ctr, ChecksumModule, CipherModule, Crypto, EmptyMap, EmptyString, JsonWallet, KdfModule,
    Sha256Checksum, TypeField, Version,
};
use eth2_wallet::{Error, Wallet};
use rand::Rng;
use uuid::Uuid;

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
    let wb = WalletBuilder::from_mnemonic(&mnemonic, &pass, wallet_name)?;
    let wallet = match wb.build() {
        Ok(w) => w,
        Err(e) => {
            return Err(e);
        }
    };
    Ok((wallet, seed_phrase))
}

pub struct WalletBuilder<'a> {
    seed: PlainText,
    password: &'a [u8],
    kdf: Kdf,
    cipher: Cipher,
    uuid: Uuid,
    name: String,
    nextaccount: u32,
}

impl<'a> WalletBuilder<'a> {
    /// Creates a new builder for a seed specified as a BIP-39 `Mnemonic` (where the nmemonic itself does
    /// not have a passphrase).
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn from_mnemonic(
        mnemonic: &Mnemonic,
        password: &'a [u8],
        name: String,
    ) -> Result<Self, Error> {
        let seed = Bip39Seed::new(mnemonic, "");

        Self::from_seed_bytes(seed.as_bytes(), password, name)
    }

    /// Creates a new builder from a `seed` specified as a byte slice.
    ///
    /// ## Errors
    ///
    /// Returns `Error::EmptyPassword` if `password == ""`.
    pub fn from_seed_bytes(seed: &[u8], password: &'a [u8], name: String) -> Result<Self, Error> {
        if password.is_empty() {
            Err(Error::EmptyPassword)
        } else if seed.is_empty() {
            Err(Error::EmptySeed)
        } else {
            let iv = rand::thread_rng().gen::<[u8; IV_SIZE]>().to_vec().into();

            Ok(Self {
                seed: seed.to_vec().into(),
                password,
                kdf: pbkdf2(),
                cipher: Cipher::Aes128Ctr(Aes128Ctr { iv }),
                uuid: Uuid::new_v4(),
                nextaccount: 0,
                name,
            })
        }
    }

    /// Consumes `self`, returning an encrypted `Wallet`.
    pub fn build(self) -> Result<Wallet, Error> {
        let (cipher_text, checksum) =
            encrypt(self.seed.as_bytes(), self.password, &self.kdf, &self.cipher)?;

        let json_wallet = JsonWallet {
            crypto: Crypto {
                kdf: KdfModule {
                    function: self.kdf.function(),
                    params: self.kdf,
                    message: EmptyString,
                },
                checksum: ChecksumModule {
                    function: Sha256Checksum::function(),
                    params: EmptyMap,
                    message: checksum.to_vec().into(),
                },
                cipher: CipherModule {
                    function: self.cipher.function(),
                    params: self.cipher,
                    message: cipher_text.into(),
                },
            },
            uuid: self.uuid,
            nextaccount: self.nextaccount,
            version: Version::one(),
            type_field: TypeField::Hd,
            name: self.name,
        };
        let wallet = Wallet::from_json_str(serde_json::to_string(&json_wallet).unwrap().as_str())?;
        Ok(wallet)
    }
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
