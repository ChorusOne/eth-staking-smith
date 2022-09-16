use crate::utils::pbkdf2;
use bip39::Seed as Bip39Seed;
use eth2_key_derivation::DerivedKey;
use eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder, PlainText};
use eth2_wallet::{KeyType, ValidatorPath};
use types::{Keypair, PublicKey};

/// Contains keystore encrypted with password, along with original voting secret.
#[derive(PartialEq)]
pub struct KeyMaterial {
    pub keystore: Keystore,
    pub voting_secret: PlainText,
    pub withdrawal_pk: Option<PublicKey>,
}

/// Given eth2 wallet seed, create N key material wrappers,
/// with voting secret and keystore encrypted with password.
pub(crate) fn seed_to_keystores(
    seed: &Bip39Seed,
    n: u32,
    password: &[u8],
    derive_withdrawal: bool,
) -> Vec<KeyMaterial> {
    (0..n)
        .map(|idx| {
            let master = DerivedKey::from_seed(seed.as_bytes()).expect("Invalid seed is provided");
            let (voting_path, voting_secret, keypair) =
                derive_keypair(master, idx, KeyType::Voting);
            let keystore = // Use pbkdf2 crypt because it is faster
            KeystoreBuilder::new(&keypair, password, format!("{}", voting_path))
                .expect("Can not create KeystoreBuilder from provided seed")
                .kdf(pbkdf2())
                .build()
                .expect("Failed to build keystore");

            let withdrawal_pk = if derive_withdrawal {
                let master =
                    DerivedKey::from_seed(seed.as_bytes()).expect("Invalid seed is provided");
                let (_, _, withdrawal_keypair) = derive_keypair(master, idx, KeyType::Withdrawal);
                Some(withdrawal_keypair.pk)
            } else {
                None
            };

            KeyMaterial {
                keystore,
                voting_secret,
                withdrawal_pk,
            }
        })
        .collect()
}

fn derive_keypair(
    master: DerivedKey,
    idx: u32,
    key_type: KeyType,
) -> (ValidatorPath, PlainText, Keypair) {
    let voting_path = ValidatorPath::new(idx, key_type);
    let voting_destination = voting_path.iter_nodes().fold(master, |dk, i| dk.child(*i));
    let voting_secret: PlainText = voting_destination.secret().to_vec().into();
    let keypair = keypair_from_secret(voting_secret.as_bytes())
        .expect("Can not initialize keypair from provided seed");
    (voting_path, voting_secret, keypair)
}

#[cfg(test)]
mod test {

    use super::seed_to_keystores;
    use bip39::{Language, Mnemonic, Seed};
    use eth2_wallet::*;
    use pretty_assertions::assert_eq;
    use test_log::test;

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";
    const VOTING_KEYSTORE_PASSWORD: &[u8] = &[44; 44];

    fn seed_from_mnemonic() -> Seed {
        let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
        Seed::new(&mnemonic, "")
    }
    #[test]
    fn test_seed_to_keystore() {
        let seed = seed_from_mnemonic();
        let keystores = seed_to_keystores(&seed, 2, VOTING_KEYSTORE_PASSWORD, false);

        assert_eq!(keystores.len(), 2);

        let key_material = keystores.get(0).unwrap();

        // Keys asserted here are generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --eth1_withdrawal_address 0x0000000000000000000000000000000000000001 --keystore_password test

        // **[Warning] you are setting an Eth1 address as your withdrawal address. Please ensure that you have control over this address.**

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        assert_eq!(key_material.keystore.pubkey(), "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6");

        let secret_key = &key_material.voting_secret;
        assert_eq!(
            "3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c",
            hex::encode(secret_key.as_bytes())
        );
    }

    #[test]
    fn test_seed_to_keystore_derive_withdrawal_key() {
        let seed = seed_from_mnemonic();
        let keystores = seed_to_keystores(&seed, 2, VOTING_KEYSTORE_PASSWORD, true);

        assert_eq!(keystores.len(), 2);

        let key_material = keystores.get(0).unwrap();

        // Keys asserted here are generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --eth1_withdrawal_address 0x0000000000000000000000000000000000000001 --keystore_password test

        // **[Warning] you are setting an Eth1 address as your withdrawal address. Please ensure that you have control over this address.**

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        assert_eq!(key_material.keystore.pubkey(), "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6");
        assert_eq!(key_material.withdrawal_pk.as_ref().unwrap().to_string(), "0x8478fed8676e9e5d0376c2da97a9e2d67ff5aa11b312aca7856b29f595fcf2c5909c8bafce82f46d9888cd18f780e302");
    }
}
