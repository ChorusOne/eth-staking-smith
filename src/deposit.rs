use eth2_keystore::keypair_from_secret;
use types::{ChainSpec, DepositData, Hash256, Signature};

use crate::{
    chain_spec::{chain_spec_for_network, chain_spec_from_file},
    key_material::VotingKeyMaterial,
    networks::SupportedNetworks,
};

#[derive(Debug, Eq, PartialEq)]
pub enum DepositError {
    InvalidWithdrawalCredentials(String),
    InvalidDepositAmount(String),
    InvalidKeystore(String),
    InvalidNetworkName(String),
    NoCustomConfig(String),
    SerializationError(String),
}

/// Given the network specification, validator keystore
/// and withdrawal credentials
/// generate deposit data
pub(crate) fn keystore_to_deposit(
    key_material: &VotingKeyMaterial,
    // withdrawal credentials
    withdrawal_credentials: &[u8],
    deposit_amount_gwei: u64,
    network: Option<SupportedNetworks>,
    chain_spec_file: Option<String>,
) -> Result<(DepositData, ChainSpec), DepositError> {
    // Validate data input

    if withdrawal_credentials.len() != 32 {
        return Err(DepositError::InvalidWithdrawalCredentials(
            "Invalid withdrawal credentials length, should be 32".to_string(),
        ));
    };

    // For simplicity, support only 32Eth deposits
    if deposit_amount_gwei != 32_000_000_000 {
        return Err(DepositError::InvalidDepositAmount(
            "Invalid amount of deposit data, should be 32Eth".to_string(),
        ));
    };

    let spec = match network {
        Some(chain) => chain_spec_for_network(&chain)?,
        None => chain_spec_from_file(chain_spec_file.unwrap())?,
    };

    let credentials_hash = Hash256::from_slice(withdrawal_credentials);

    let keypair = match keypair_from_secret(key_material.voting_secret.as_bytes()) {
        Ok(kp) => kp,
        Err(e) => {
            log::debug!("Invalid voting key material passed: {:?}", e);
            return Err(DepositError::InvalidKeystore(
                "Invalid key material or password".to_string(),
            ));
        }
    };

    let mut deposit_data = DepositData {
        pubkey: keypair.pk.clone().into(),
        withdrawal_credentials: credentials_hash,
        amount: deposit_amount_gwei,
        signature: Signature::empty().into(),
    };

    deposit_data.signature = deposit_data.create_signature(&keypair.sk, &spec);
    Ok((deposit_data, spec))
}

#[cfg(test)]
mod test {

    use eth2_keystore::{Keystore, PlainText};
    use pretty_assertions::assert_eq;
    use types::PublicKey;

    use super::keystore_to_deposit;
    use crate::{key_material::VotingKeyMaterial, utils::get_withdrawal_credentials};
    use std::{path::PathBuf, str::FromStr};
    use test_log::test;

    const KEYSTORE: &str = r#"{"crypto": {"kdf": {"function": "scrypt", "params": {"dklen": 32, "n": 262144, "r": 8, "p": 1, "salt": "b304b4590787ca795e4d9b4b0d15789063899db8fc0a9bc55739a5c7c4fc046e"}, "message": ""}, "checksum": {"function": "sha256", "params": {}, "message": "ab4a1de483a5b93c93aeaa6e5cae0603c8cdc8105be4581c52dcc48895e2aa98"}, "cipher": {"function": "aes-128-ctr", "params": {"iv": "36738842a9bfe988c385475314bb5ecb"}, "message": "c154a583e467cdf3e6010b65fcb96308e591bde8caca4b4df805ecd0d1809b0e"}}, "description": "", "pubkey": "8666389c3fe6ff0bca9adba81504f380b9e2c719419760d561836472fafe295cb50696524e19cba084e1d788d66c80d6", "path": "m/12381/3600/0/0/0", "uuid": "296e52b6-deee-4302-b970-9fce9f7269ac", "version": 4}"#;
    const PASSWORD: &[u8] = "test".as_bytes();
    const WITHDRAWAL_CREDENTIALS_ETH1: &[u8] =
        "0100000000000000000000000000000000000000000000000000000000000001".as_bytes();
    const WITHDRAWAL_CREDENTIALS_ETH2: &[u8] =
        "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7".as_bytes();

    #[test]
    fn test_deposit_mainnet_eth1_withdrawal() {
        let withdrawal_creds = hex::decode(WITHDRAWAL_CREDENTIALS_ETH1).unwrap();

        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair: keypair.clone(),
            voting_secret: PlainText::from(keypair.sk.serialize().as_bytes().to_vec()),
            withdrawal_keypair: None,
        };
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            withdrawal_creds.as_slice(),
            32_000_000_000,
            Some(crate::networks::SupportedNetworks::Mainnet),
            None,
        )
        .unwrap();

        // Signature asserted here is generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --eth1_withdrawal_address 0x010000000000000000000000000000000000000001 --keystore_password test

        // **[Warning] you are setting an Eth1 address as your withdrawal address. Please ensure that you have control over this address.**

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

        assert_eq!(
            "a1f3ece1cb871e1af29fdaf94cab58d48d128d0ed2342a1f042f49344943c25ec6eab4f2219301e421a88453c6aa29e90b78373a8341c17738bc0ff4d0a724494535b494cd21fd2633a7a12353a5232c9806e1576f1e2447631ec3310db4008b",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
        assert_eq!(
            "0100000000000000000000000000000000000000000000000000000000000001",
            hex::encode(deposit_data.withdrawal_credentials)
        );
    }

    #[test]
    fn test_deposit_mainnet_eth2_withdrawal() {
        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair: keypair.clone(),
            voting_secret: PlainText::from(keypair.sk.serialize().as_bytes().to_vec()),
            withdrawal_keypair: None,
        };
        let withdrawal_creds = hex::decode(WITHDRAWAL_CREDENTIALS_ETH2).unwrap();
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            withdrawal_creds.as_slice(),
            32_000_000_000,
            Some(crate::networks::SupportedNetworks::Mainnet),
            None,
        )
        .unwrap();

        // Signature asserted here is generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --keystore_password test

        println!("{:?}", deposit_data);

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal
        assert_eq!(
            "8fb5a76232cb613c30e02b5946d252d0cc5ed8cfa81b7a1f781dc4f228c5e89e77b5b745fba4371be8ea7f02f6b7e18e0e3661b04a63d51197bd43b9dea27fef97b8e2b94ffc989fc29484537bfed9f99b6bc57b45c2004dd23e1502006640d4",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
        assert_eq!(
            "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
            hex::encode(deposit_data.withdrawal_credentials)
        );
    }

    #[test]
    fn test_deposit_mainnet_no_withdrawal() {
        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let pk = PublicKey::from_str(&"0x8478fed8676e9e5d0376c2da97a9e2d67ff5aa11b312aca7856b29f595fcf2c5909c8bafce82f46d9888cd18f780e302").unwrap();
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair: keypair.clone(),
            voting_secret: PlainText::from(keypair.sk.serialize().as_bytes().to_vec()),
            withdrawal_keypair: Some(keypair.clone()),
        };
        let withdrawal_creds = get_withdrawal_credentials(&pk.into(), 0);
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            &withdrawal_creds,
            32_000_000_000,
            Some(crate::networks::SupportedNetworks::Mainnet),
            None,
        )
        .unwrap();

        println!("{:?}", deposit_data);

        // Signature asserted here is generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --keystore_password test

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal
        assert_eq!(
            "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
            hex::encode(deposit_data.withdrawal_credentials)
        );
        assert_eq!(
            "8fb5a76232cb613c30e02b5946d252d0cc5ed8cfa81b7a1f781dc4f228c5e89e77b5b745fba4371be8ea7f02f6b7e18e0e3661b04a63d51197bd43b9dea27fef97b8e2b94ffc989fc29484537bfed9f99b6bc57b45c2004dd23e1502006640d4",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
    }

    #[test]
    fn test_deposit_goerli() {
        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair,
            voting_secret: PlainText::from(
                keystore
                    .decrypt_keypair(PASSWORD)
                    .unwrap()
                    .sk
                    .serialize()
                    .as_bytes()
                    .to_vec(),
            ),
            withdrawal_keypair: None,
        };
        let withdrawal_creds = hex::decode(WITHDRAWAL_CREDENTIALS_ETH2).unwrap();
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            &withdrawal_creds.as_slice(),
            32_000_000_000,
            Some(crate::networks::SupportedNetworks::Goerli),
            None,
        )
        .unwrap();

        // Signature asserted here is generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --keystore_password test

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: prater
        assert_eq!(
            "aa954f22199db5ceb3f3b4b76740408af43cabf5724af5db530f7452f204b44026809e145003827b3c9cbd979bb035a3160b2f231aec3ccabc4fe039030a8baf36b4ad5d458ba672714f327e4705f14c501c3184b9c1fd171470c5170002fa8c",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
    }

    #[test]
    fn test_deposit_holesky() {
        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair,
            voting_secret: PlainText::from(
                keystore
                    .decrypt_keypair(PASSWORD)
                    .unwrap()
                    .sk
                    .serialize()
                    .as_bytes()
                    .to_vec(),
            ),
            withdrawal_keypair: None,
        };
        let withdrawal_creds = hex::decode(WITHDRAWAL_CREDENTIALS_ETH2).unwrap();
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            &withdrawal_creds.as_slice(),
            32_000_000_000,
            Some(crate::networks::SupportedNetworks::Holesky),
            None,
        )
        .unwrap();

        // python ./staking_deposit/deposit.py existing-mnemonic --keystore_password testtest

        // ***Using the tool on an offline and secure device is highly recommended to keep your mnemonic safe.***

        // Please choose your language ['1. العربية', '2. ελληνικά', '3. English', '4. Français', '5. Bahasa melayu', '6. Italiano', '7. 日本語', '8. 한국어', '9. Português do Brasil', '10. român', '11. Türkçe', '12. 简体中文']:  [English]:
        // Repeat your keystore password for confirmation:
        // Please enter your mnemonic separated by spaces (" "). Note: you only need to enter the first 4 letters of each word if you'd prefer.: entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]:
        // Please repeat the index to confirm: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'goerli', 'sepolia', 'zhejiang', 'holesky']:  [mainnet]: holesky
        assert_eq!(
            "9631e3c0eb64e2ee89341fef9a7323a9f657ee4a62d22a685c72c813cca561ede5446ff1ee58cb073fdd9bc5932d3bbe00bbfe28cd15c85fd044856e3360ebcc5b1b3b884c63ed25d3ebf444f76c103213bb1bc258e94c7325379ad4da412a8e",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
    }

    #[test]
    fn test_deposit_custom_testnet() {
        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let mut manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest.push("tests/resources/helder-testnet.yaml");
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair: keypair.clone(),
            voting_secret: PlainText::from(keypair.sk.serialize().as_bytes().to_vec()),
            withdrawal_keypair: None,
        };
        let withdrawal_creds = hex::decode(WITHDRAWAL_CREDENTIALS_ETH2).unwrap();
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            &withdrawal_creds.as_slice(),
            32_000_000_000,
            None,
            Some(manifest.to_str().unwrap().to_owned()),
        )
        .unwrap();

        // Signature asserted here is generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --keystore_password test

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal
        assert_eq!(
            "974ab2ce579f12339bb3125311a4d69f50e8d40546d086629f8f9af31ef7ee1fd0400b40d1884f7f0487b17069054b6305eb8321e883a5110e7e67864da44e4e15efbed5ff752a1a93bada4f53cdd033d8884233925546e28b16991d44307d8d",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
    }

    #[test]
    fn test_deposit_custom_minimal_testnet() {
        let keystore = Keystore::from_json_str(KEYSTORE).unwrap();
        let keypair = keystore.decrypt_keypair(PASSWORD).unwrap();
        let mut manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        manifest.push("tests/resources/minimal.yaml");
        let key_material = VotingKeyMaterial {
            keystore: Some(keystore.clone()),
            keypair: keypair.clone(),
            voting_secret: PlainText::from(keypair.sk.serialize().as_bytes().to_vec()),
            withdrawal_keypair: None,
        };
        let withdrawal_creds = hex::decode(WITHDRAWAL_CREDENTIALS_ETH2).unwrap();
        let (deposit_data, _) = keystore_to_deposit(
            &key_material,
            &withdrawal_creds.as_slice(),
            32_000_000_000,
            None,
            Some(manifest.to_str().unwrap().to_owned()),
        )
        .unwrap();

        // Signature asserted here is generated with
        // python ./staking_deposit/deposit.py existing-mnemonic --keystore_password test

        // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
        // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
        // Please choose how many new validators you wish to run: 1
        // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal
        assert_eq!(
            "ad1c1e0d3b230e2d3a1366c0bef83dcb8ce7ac7827353b74ed7abea2153e06638f338226925e141dd74c13a41c6f602f13a70ccf3ca74e76739810c20a76f6a5b71d9bd2e093a13a97ad8eb7ad0e3ce3e5b3c172af2dc9b8368fe3f645345aee",
            deposit_data.signature.to_string().as_str().strip_prefix("0x").unwrap()
        );
    }
}
