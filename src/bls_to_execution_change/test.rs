use std::str::FromStr;

use types::{Hash256, PublicKey};

use crate::{chain_spec, networks::validators_root_for, utils};

const EXECUTION_WITHDRAWAL_ADDRESS: &str = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
const PHRASE: &str = "entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup";

#[test]
fn it_generates_signed_bls_to_execution_change_hoodi() {
    // Keys asserted here are generated with the staking-deposit cli
    // ./deposit existing-mnemonic --keystore_password testtest

    // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
    // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
    // Please choose how many new validators you wish to run: 1
    // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'goerli', 'sepolia', 'holesky']:  [mainnet]: hoodi

    fn withdrawal_creds_from_pk(withdrawal_pk: &PublicKey) -> String {
        let withdrawal_creds = utils::get_withdrawal_credentials(&withdrawal_pk.into(), 0);
        let credentials_hash = Hash256::from_slice(&withdrawal_creds);
        hex::encode(&credentials_hash.as_slice())
    }

    let (bls_to_execution_change, keypair) =
        crate::bls_to_execution_change::bls_execution_change_from_mnemonic(
            PHRASE.as_bytes(),
            0,
            100,
            EXECUTION_WITHDRAWAL_ADDRESS,
        );
    let signed_bls_to_execution_change = bls_to_execution_change.clone().sign(
        &keypair.withdrawal_keypair.unwrap().sk,
        validators_root_for(&crate::networks::SupportedNetworks::Hoodi),
        &chain_spec::chain_spec_for_network(&crate::networks::SupportedNetworks::Hoodi).unwrap(),
    );

    // format generated fields for assertion
    let to_execution_address = &signed_bls_to_execution_change.message.to_execution_address;

    let withdrawal_pub_key_str = &signed_bls_to_execution_change.message.from_bls_pubkey;
    let withdrawal_pub_key = PublicKey::from_str(&withdrawal_pub_key_str.to_string()).unwrap();

    let validator_index = bls_to_execution_change.clone().validator_index;

    assert_eq!(100, validator_index);
    assert_eq!(
        EXECUTION_WITHDRAWAL_ADDRESS.to_lowercase(),
        format!("0x{}", hex::encode(to_execution_address)),
    );
    assert_eq!(
        "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
        withdrawal_creds_from_pk(&withdrawal_pub_key)
    );

    // Print the signature for debugging
    println!("Hoodi BLS signature: {}", signed_bls_to_execution_change.signature);
}

#[test]
fn it_generates_signed_bls_to_execution_change() {
    // Keys asserted here are generated with the staking-deposit cli
    // ./deposit existing-mnemonic --keystore_password testtest

    // Please enter your mnemonic separated by spaces (" "): entire habit bottom mention spoil clown finger wheat motion fox axis mechanic country make garment bar blind stadium sugar water scissors canyon often ketchup
    // Enter the index (key number) you wish to start generating more keys from. For example, if you've generated 4 keys in the past, you'd enter 4 here. [0]: 0
    // Please choose how many new validators you wish to run: 1
    // Please choose the (mainnet or testnet) network/chain name ['mainnet', 'prater', 'kintsugi', 'kiln', 'minimal']:  [mainnet]: minimal

    fn withdrawal_creds_from_pk(withdrawal_pk: &PublicKey) -> String {
        let withdrawal_creds = utils::get_withdrawal_credentials(&withdrawal_pk.into(), 0);
        let credentials_hash = Hash256::from_slice(&withdrawal_creds);
        hex::encode(&credentials_hash.as_slice())
    }

    let (bls_to_execution_change, keypair) =
        crate::bls_to_execution_change::bls_execution_change_from_mnemonic(
            PHRASE.as_bytes(),
            0,
            100,
            EXECUTION_WITHDRAWAL_ADDRESS,
        );
    let signed_bls_to_execution_change = bls_to_execution_change.clone().sign(
        &keypair.withdrawal_keypair.unwrap().sk,
        validators_root_for(&crate::networks::SupportedNetworks::Mainnet),
        &chain_spec::chain_spec_for_network(&crate::networks::SupportedNetworks::Mainnet).unwrap(),
    );

    // format generated fields for assertion
    let to_execution_address = &signed_bls_to_execution_change.message.to_execution_address;

    let withdrawal_pub_key_str = &signed_bls_to_execution_change.message.from_bls_pubkey;
    let withdrawal_pub_key = PublicKey::from_str(&withdrawal_pub_key_str.to_string()).unwrap();

    let validator_index = bls_to_execution_change.clone().validator_index;

    assert_eq!(100, validator_index);
    assert_eq!(
        EXECUTION_WITHDRAWAL_ADDRESS.to_lowercase(),
        format!("0x{}", hex::encode(to_execution_address)),
    );
    assert_eq!(
        "00e078f11bc1454244bdf9f63a3b997815f081dd6630204186d4c9627a2942f7",
        withdrawal_creds_from_pk(&withdrawal_pub_key)
    );
}
