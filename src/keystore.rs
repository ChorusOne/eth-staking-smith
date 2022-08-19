use crate::utils::pbkdf2;
use bip39::Seed as Bip39Seed;
use eth2_key_derivation::DerivedKey;
use eth2_keystore::{keypair_from_secret, Keystore, KeystoreBuilder, PlainText};
use eth2_wallet::{KeyType, ValidatorPath};

/// Given eth2 wallet, create N keystores encrypted with password.
pub(crate) fn wallet_to_keystores(wallet: &Bip39Seed, n: u32, password: &[u8]) -> Vec<Keystore> {
    (0..n)
        .map(|idx| {
            let master =
                DerivedKey::from_seed(wallet.as_bytes()).expect("Invalid seed is provided");
            let path = ValidatorPath::new(idx, KeyType::Voting);
            let destination = path.iter_nodes().fold(master, |dk, i| dk.child(*i));
            let voting_secret: PlainText = destination.secret().to_vec().into();

            let keypair = keypair_from_secret(voting_secret.as_bytes())
                .expect("Can not initialize keypair from provided wallet");

            // Use pbkdf2 crypt because it is faster
            KeystoreBuilder::new(&keypair, password, format!("{}", path))
                .expect("Can not create KeystoreBuilder from provided wallet")
                .kdf(pbkdf2())
                .build()
                .expect("Failed to build keystore")
        })
        .collect()
}

#[cfg(test)]
mod test {

    use super::wallet_to_keystores;
    use bip39::{Language, Mnemonic, Seed};
    use eth2_wallet::*;
    use pretty_assertions::assert_eq;
    use test_log::test;

    const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";
    const VOTING_KEYSTORE_PASSWORD: &[u8] = &[44; 44];

    fn wallet_from_seed() -> Seed {
        let mnemonic = Mnemonic::from_phrase(PHRASE, Language::English).unwrap();
        Seed::new(&mnemonic, "")
    }
    #[test]
    fn test_wallet_to_keystore() {
        let wallet = wallet_from_seed();
        let keystores = wallet_to_keystores(&wallet, 2, VOTING_KEYSTORE_PASSWORD);

        assert_eq!(keystores.len(), 2);

        let keystore = keystores.get(0).unwrap();

        // Keys asserted here are generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --eth1_withdrawal_address 0x0000000000000000000000000000000000000001 --keystore_password test

        // **[Warning] you are setting an Eth1 address as your withdrawal address. Please ensure that you have control over this address.**

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        assert_eq!(keystore.pubkey(), "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6");

        let secret_key = keystore
            .decrypt_keypair(VOTING_KEYSTORE_PASSWORD)
            .unwrap()
            .sk
            .serialize();
        assert_eq!(
            "3f3e0a69a6a66aeaec606a2ccb47c703afb2e8ae64f70a1650c03343b06e8f0c",
            hex::encode(secret_key.as_bytes())
        );
    }
}
