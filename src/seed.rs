use bip39::{Language, Mnemonic, MnemonicType, Seed as Bip39Seed};
use rand::{rngs::OsRng, RngCore};

fn create_new_seed() -> Mnemonic {
    let mut bytes = vec![0u8; MnemonicType::Words24.entropy_bits() / 8];

    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("Failed to fill bytes from random generator");

    Mnemonic::from_entropy(bytes.as_slice(), Language::English)
        .expect("Failed to generate mnemonic")
}

pub(crate) fn get_eth2_seed(existing_mnemonic: Option<&[u8]>) -> (Bip39Seed, String) {
    let mnemonic = match existing_mnemonic {
        Some(found_mnemonic) => {
            let phrase = std::str::from_utf8(found_mnemonic).unwrap().to_string();
            Mnemonic::from_phrase(phrase.as_str(), Language::English)
                .expect("Invalid phrase passed")
        }
        None => create_new_seed(),
    };
    (Bip39Seed::new(&mnemonic, ""), mnemonic.into_phrase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";
    // Since it is impossible to recover phrase from seed,
    // use internal seed as an etalon here.
    const PHRASE_SEED: &str = "5017c7d08b4b15b05e7f03df3c36b3597eb38ac1bb68b0a33f93262b035e555417288484c982e9c3d1831be2ec5acf6d49230bd3f25d22bf8dd35677c12da7c3";

    #[test]
    fn it_creates_seed_with_new_mnemonic() {
        let (seed, _) = get_eth2_seed(None);
        assert_ne!(PHRASE_SEED, hex::encode(seed.as_bytes()));
    }

    #[test]
    fn it_creates_seed_with_existing_mnemonic() {
        let (seed, _) = get_eth2_seed(Some(PHRASE.as_bytes()));
        assert_eq!(PHRASE_SEED, hex::encode(seed.as_bytes()));
    }
}
