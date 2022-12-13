use crate::utils::pbkdf2;
use bip39::Seed as Bip39Seed;
use eth2_key_derivation::DerivedKey;
use eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder, PlainText};
use eth2_wallet::{KeyType, ValidatorPath};
use types::{Keypair, PublicKey};

/// Contains keystore encrypted with password, along with original voting secret.
#[derive(Clone)]
pub struct VotingKeyMaterial {
    pub keystore: Option<Keystore>,
    pub keypair: Keypair,
    pub voting_secret: PlainText,
    pub withdrawal_pk: Option<PublicKey>,
}

/// Given eth2 wallet seed, create N key material wrappers,
/// with voting secret and keystore encrypted with password.
pub(crate) fn seed_to_key_material(
    seed: &Bip39Seed,
    n: u32,
    start_index: u32,
    password: Option<&[u8]>,
    derive_withdrawal: bool,
) -> Vec<VotingKeyMaterial> {
    (start_index..start_index + n)
        .map(|idx| {
            let master = DerivedKey::from_seed(seed.as_bytes()).expect("Invalid seed is provided");
            let (voting_path, voting_secret, keypair) =
                derive_keypair(master, idx, KeyType::Voting);
            let keystore = // Use pbkdf2 crypt because it is faster
                password.map(
                    |pass| {
                        if pass.len() < 8 { panic!("The password length should be at least 8"); }
                        KeystoreBuilder::new(&keypair, pass, format!("{}", voting_path))
                            .expect("Can not create KeystoreBuilder from provided seed")
                            .kdf(pbkdf2())
                            .build()
                            .expect("Failed to build keystore")
                    }
                );

            let withdrawal_pk = if derive_withdrawal {
                let master =
                    DerivedKey::from_seed(seed.as_bytes()).expect("Invalid seed is provided");
                let (_, _, withdrawal_keypair) = derive_keypair(master, idx, KeyType::Withdrawal);
                Some(withdrawal_keypair.pk)
            } else {
                None
            };

            VotingKeyMaterial {
                keystore,
                keypair,
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

    use crate::utils;

    use super::seed_to_key_material;
    use bip39::{Language, Mnemonic, Seed};
    use eth2_wallet::*;
    use pretty_assertions::assert_eq;
    use test_log::test;
    use types::{Hash256, PublicKey};

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";
    const VOTING_KEYSTORE_PASSWORD: &[u8] = &[44; 44];

    fn seed_from_mnemonic() -> Seed {
        let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
        Seed::new(&mnemonic, "")
    }
    fn withdrawal_creds_from_pk(withdrawal_pk: &PublicKey) -> String {
        let withdrawal_creds = utils::get_withdrawal_credentials(&withdrawal_pk, 0);
        let credentials_hash = Hash256::from_slice(&withdrawal_creds);
        hex::encode(&credentials_hash.as_bytes())
    }
    #[test]
    fn test_seed_to_keystore() {
        let seed = seed_from_mnemonic();
        let keystores = seed_to_key_material(&seed, 3, 0, Some(VOTING_KEYSTORE_PASSWORD), false);

        assert_eq!(keystores.len(), 3);

        // Keys asserted here are generated with
        // ./deposit existing-mnemonic --eth1_withdrawal_address 0x0000000000000000000000000000000000000001 --keystore_password testtest

        // **[Warning] you are setting an Eth1 address as your withdrawal address. Please ensure that you have control over this address.**

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 3
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        let key_material_1 = keystores.get(0).unwrap();
        assert_eq!(key_material_1.clone().keystore.unwrap().pubkey(), "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6");
        let secret_key = &key_material_1.voting_secret;
        assert_eq!(
            "3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c",
            hex::encode(secret_key.as_bytes())
        );
        assert!(key_material_1.withdrawal_pk.is_none()); // we didn't derive a pk, but will set the one passed in

        let key_material_2 = keystores.get(1).unwrap();
        assert_eq!(key_material_2.clone().keystore.unwrap().pubkey(), "974ec5bce4653f1f440ad07c5b363ad3b1616520e9680ff837f9ff7a8c10e3cc67dd49aa5089f714ed45d7ad56bc758a");
        let secret_key = &key_material_2.voting_secret;
        assert_eq!(
            "5b17290ac4e36c497378351ed61253a239d408466918fe5a8dd79b28ef67f9df",
            hex::encode(secret_key.as_bytes())
        );
        assert!(key_material_2.withdrawal_pk.is_none()); // we didn't derive a pk, but will set the one passed in

        let key_material_3 = keystores.get(2).unwrap();
        assert_eq!(key_material_3.clone().keystore.unwrap().pubkey(), "8bf0a669a51d0cb6ff745e4b0aa7c41e8de8d179ff9267977e76c7188aaa2fb1b8b1bdfefcc545d9efdac0b4bc2239e6");
        let secret_key = &key_material_3.voting_secret;
        assert_eq!(
            "1cb46382c3c046f7817298d1ad3454a7175be6e53059bdd287e8fcbf4c6fb2e8",
            hex::encode(secret_key.as_bytes())
        );
        assert!(key_material_3.withdrawal_pk.is_none()); // we didn't derive a pk, but will set the one passed in
    }

    #[test]
    fn test_seed_to_keystore_derive_withdrawal_key() {
        let seed = seed_from_mnemonic();
        let keystores = seed_to_key_material(&seed, 3, 0, Some(VOTING_KEYSTORE_PASSWORD), true);

        assert_eq!(keystores.len(), 3);

        // Keys asserted here are generated with
        // ./deposit existing-mnemonic --keystore_password testtest

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 3
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        let key_material_1 = keystores.get(0).unwrap();
        assert_eq!(key_material_1.clone().keystore.unwrap().pubkey(), "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6");
        assert_eq!(
            "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
            withdrawal_creds_from_pk(key_material_1.withdrawal_pk.as_ref().unwrap())
        );

        let key_material_2 = keystores.get(1).unwrap();
        assert_eq!(key_material_2.clone().keystore.unwrap().pubkey(), "974ec5bce4653f1f440ad07c5b363ad3b1616520e9680ff837f9ff7a8c10e3cc67dd49aa5089f714ed45d7ad56bc758a");
        assert_eq!(
            "00df91f98d1b3f858c0a8f0ca9de217214413af3fa3ee2ef7f1624418c3afacb",
            withdrawal_creds_from_pk(key_material_2.withdrawal_pk.as_ref().unwrap())
        );

        let key_material_3 = keystores.get(2).unwrap();
        assert_eq!(key_material_3.clone().keystore.unwrap().pubkey(), "8bf0a669a51d0cb6ff745e4b0aa7c41e8de8d179ff9267977e76c7188aaa2fb1b8b1bdfefcc545d9efdac0b4bc2239e6");
        assert_eq!(
            "0036af360f452c1e241e32b1c766ea8dfb7e8c373f9111d758ec1aaf9590e80e",
            withdrawal_creds_from_pk(key_material_3.withdrawal_pk.as_ref().unwrap())
        );
    }

    #[test]
    fn test_key_material_no_keystore() {
        let seed = seed_from_mnemonic();
        let keystores = seed_to_key_material(&seed, 2, 0, None, true);

        assert_eq!(keystores.len(), 2);

        let key_material = keystores.get(0).unwrap();

        // Keystore is missing.
        assert_eq!(None, key_material.keystore);
    }

    /*
        this test case simulates the fact when we want to regenerate data for a specific key
        should be the same as above, but only return the 2nd key we want to regenerate
    */
    #[test]
    fn test_seed_to_keystore_start_index() {
        let seed = seed_from_mnemonic();

        let keystores = seed_to_key_material(&seed, 2, 1, Some(VOTING_KEYSTORE_PASSWORD), true);

        assert_eq!(keystores.len(), 2);

        // Keys asserted here are generated with
        // ./deposit existing-mnemonic --keystore_password testtest

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 1
        // Please choose how many new validators you wish to run: 2
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        let key_material_2 = keystores.get(0).unwrap();
        assert_eq!(key_material_2.clone().keystore.unwrap().pubkey(), "974ec5bce4653f1f440ad07c5b363ad3b1616520e9680ff837f9ff7a8c10e3cc67dd49aa5089f714ed45d7ad56bc758a");
        assert_eq!(
            "00df91f98d1b3f858c0a8f0ca9de217214413af3fa3ee2ef7f1624418c3afacb",
            withdrawal_creds_from_pk(key_material_2.withdrawal_pk.as_ref().unwrap())
        );

        let key_material_3 = keystores.get(1).unwrap();
        assert_eq!(key_material_3.clone().keystore.unwrap().pubkey(), "8bf0a669a51d0cb6ff745e4b0aa7c41e8de8d179ff9267977e76c7188aaa2fb1b8b1bdfefcc545d9efdac0b4bc2239e6");
        assert_eq!(
            "0036af360f452c1e241e32b1c766ea8dfb7e8c373f9111d758ec1aaf9590e80e",
            withdrawal_creds_from_pk(key_material_3.withdrawal_pk.as_ref().unwrap())
        );
    }
}
