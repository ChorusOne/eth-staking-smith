use assert_cmd::prelude::*;
use eth2_keystore::json_keystore::{Crypto, JsonKeystore};
use eth_staking_smith::ValidatorExports;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    str::FromStr,
};

use crate::e2e::DepositDataJson;

/*
    generate 1 validator (with no withdrawal address specified, i.e. the address is derived from the public key)
*/
#[test]
fn test_existing_mnemonic_testcase1() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let num_validators = "1";

    // test directory
    let test_dir = get_test_dir("testcase1");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1668613231.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1668613231.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    let generated_validator_json: ValidatorExports = serde_json::from_str(command_output)?;
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with eth1 address
*/
#[test]
fn test_existing_mnemonic_testcase2() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "anothertest";
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let execution_withdrawal_credentials = "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";

    // test directory
    let test_dir = get_test_dir("testcase2");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1669709160.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1669709160.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    println!("command_output {}", command_output);
    let generated_validator_json: ValidatorExports = serde_json::from_str(command_output)?;
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

/*
    generate 3 validators
*/
#[test]
fn test_multliple_validators_testcase3() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "blablatest";
    let expected_mnemonic = "window lottery throw arrange visit play gate open scare strategy sadness fame soul bronze soap";
    let num_validators = "3";
    let execution_withdrawal_credentials = "0x0000000000000000000000000000000000000001";

    // test directory
    let test_dir = get_test_dir("testcase3");

    // read expected files
    let expected_deposit_data_json =
        read_deposit_data_json(&test_dir, "deposit_data-1670231001.json");

    let mut expected_keystore_jsons = vec![];
    let mut index = 0;

    for entry in std::fs::read_dir(&test_dir)? {
        let filename = entry?
            .file_name()
            .to_str()
            .expect("could not read filename")
            .to_owned();
        if filename.starts_with(&format!("keystore-m_12381_3600_{}", index)) {
            let keystore_path = test_dir.join(PathBuf::from_str(&filename)?);
            let keystore_file = std::fs::read_to_string(test_dir.join(keystore_path))?;
            let expected_keystore_json = serde_json::from_str::<JsonKeystore>(&keystore_file)?;
            expected_keystore_jsons.push(expected_keystore_json);
            index = index + 1;
        }
    }

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    println!("command_output {}", command_output);
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_keys = generated_validator_json.private_keys;
    let generated_deposit_data = generated_validator_json.deposit_data;

    // decrypt keystore with expected password to derive private key and compare private keys
    for index in 0..expected_keystore_jsons.len() {
        let expected_private_key_txt = eth2_keystore::decrypt(
            expected_decryption_password.as_bytes(),
            &expected_keystore_jsons[index].crypto,
        )
        .expect("could not decrypt keystore");
        let expected_private_key = hex::encode(expected_private_key_txt.as_bytes());
        assert_eq!(
            expected_private_key,
            generated_private_keys[index].to_owned()
        );
    }

    // compare deposit data entries
    for index in 0..expected_deposit_data_json.len() {
        let expected_deposit_data_json = &expected_deposit_data_json[index];

        assert_eq!(
            expected_deposit_data_json.pubkey.to_string(),
            generated_deposit_data[index].pubkey
        );
        assert_eq!(
            expected_deposit_data_json
                .withdrawal_credentials
                .to_string(),
            generated_deposit_data[index].withdrawal_credentials
        );
        assert_eq!(
            expected_deposit_data_json.amount.to_string(),
            generated_deposit_data[index].amount.to_string()
        );
        assert_eq!(
            expected_deposit_data_json.signature.to_string(),
            generated_deposit_data[index].signature.to_string()
        );
    }

    Ok(())
}

/*
    generate 1 validator by passing in an existing bls credentials (to ensure correctness, we'll use the validator from testcase 1)
*/
#[test]
fn test_existing_mnemonic_testcase4() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "testtest";
    let expected_mnemonic = "ski interest capable knee usual ugly duty exercise tattoo subway delay upper bid forget say";
    let num_validators = "1";
    let bls_withdrawal_credentials =
        "0x0045b91b2f60b88e7392d49ae1364b55e713d06f30e563f9f99e10994b26221d";

    // test directory
    let test_dir = get_test_dir("testcase1");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1668613231.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1668613231.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(bls_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd
        .output()
        .expect("could not get output from command")
        .stdout;
    let command_output = std::str::from_utf8(output).expect("could not parse output into string");
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated deposit key");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

/*
    generate 1 validator overwriting withdrawal credentials with eth1 credentials (to ensure correctness, we'll use the validator from testcase 2)
*/
#[test]
fn test_existing_mnemonic_testcase5() -> Result<(), Box<dyn std::error::Error>> {
    let chain = "goerli";
    let expected_decryption_password = "anothertest";
    let expected_mnemonic = "satisfy suit expire castle fluid must electric genuine aim clock such under basic rabbit method";
    let num_validators = "1";
    let execution_withdrawal_credentials =
        "0x01000000000000000000000071c7656ec7ab88b098defb751b7401b5f6d8976f";

    // test directory
    let test_dir = get_test_dir("testcase2");

    // read expected files
    let expected_keystore_json =
        read_keystore_json(&test_dir, "keystore-m_12381_3600_0_0_0-1669709160.json");
    let expected_deposit_data = read_deposit_data_json(&test_dir, "deposit_data-1669709160.json");
    let expected_deposit_data_json = expected_deposit_data.get(0).unwrap();

    // decrypt keystore with expected password to derive private key
    let expected_private_key = decrypt_expected_keystore_file(
        expected_decryption_password,
        &expected_keystore_json.crypto,
    );

    // run eth-staking-smith

    let mut cmd = Command::cargo_bin("eth-staking-smith")?;

    cmd.arg("existing-mnemonic");
    cmd.arg("--chain");
    cmd.arg(chain);
    cmd.arg("--keystore_password");
    cmd.arg(expected_decryption_password);
    cmd.arg("--mnemonic");
    cmd.arg(expected_mnemonic);
    cmd.arg("--num_validators");
    cmd.arg(num_validators);
    cmd.arg("--withdrawal_credentials");
    cmd.arg(execution_withdrawal_credentials);

    cmd.assert().success();

    // read generated output

    let output = &cmd.output()?.stdout;
    let command_output = std::str::from_utf8(output)?;
    println!("command_output {}", command_output);
    let generated_validator_json: ValidatorExports =
        serde_json::from_str(command_output).expect("could not unmarshal command output");
    let generated_private_key = generated_validator_json
        .private_keys
        .get(0)
        .expect("could not get generated private key");
    let generated_deposit_data = generated_validator_json
        .deposit_data
        .get(0)
        .expect("could not get generated private key");

    // compare private keys

    assert_eq!(expected_private_key, generated_private_key.to_owned());

    // compare deposit data

    assert_eq!(
        expected_deposit_data_json.pubkey.to_string(),
        generated_deposit_data.pubkey
    );
    assert_eq!(
        expected_deposit_data_json
            .withdrawal_credentials
            .to_string(),
        generated_deposit_data.withdrawal_credentials
    );
    assert_eq!(
        expected_deposit_data_json.amount.to_string(),
        generated_deposit_data.amount.to_string()
    );
    assert_eq!(
        expected_deposit_data_json.signature.to_string(),
        generated_deposit_data.signature.to_string()
    );

    Ok(())
}

fn get_test_dir(testcase: &str) -> PathBuf {
    let cwd = env::current_dir().expect("could not get current directory");
    let test_path = cwd.join(Path::new(&format!(
        "tests/e2e/expected_testdata/{}",
        testcase
    )));
    test_path
}

fn read_keystore_json(test_path: &PathBuf, keystore_filename: &str) -> JsonKeystore {
    let keystore_path = test_path.join(Path::new(&keystore_filename));
    let keystore_file =
        std::fs::read_to_string(keystore_path).expect("could not read keystore from path");
    let expected_keystore_json = serde_json::from_str::<JsonKeystore>(&keystore_file)
        .expect("could not unmarshal keystore json");
    expected_keystore_json
}

fn decrypt_expected_keystore_file(
    expected_decryption_password: &str,
    expected_keystore_crypto: &Crypto,
) -> String {
    let expected_private_key_txt = eth2_keystore::decrypt(
        expected_decryption_password.as_bytes(),
        &expected_keystore_crypto,
    )
    .expect("could not decrypt keystore");
    let expected_private_key = hex::encode(expected_private_key_txt.as_bytes());
    expected_private_key
}

fn read_deposit_data_json(
    test_path: &PathBuf,
    deposit_data_filename: &str,
) -> Vec<DepositDataJson> {
    let deposit_data_path = test_path.join(Path::new(deposit_data_filename));
    let deposit_data_file =
        std::fs::read_to_string(deposit_data_path).expect("could not read deposit data");
    serde_json::from_str::<Vec<DepositDataJson>>(&deposit_data_file)
        .expect("could not unmarshal deposit data json")
}
